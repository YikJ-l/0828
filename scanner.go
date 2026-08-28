package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ServiceAsset struct {
	ServiceType string
	Proto       string
	Port        int
	Name        string
	IPv4        string
	IPv6        string
	Hostname    string
	TTL         uint32
	TXT         []string
}

type DeviceAsset struct {
	IP         string
	Services   []ServiceAsset
	DeviceInfo *ServiceAsset
	Answers    []string // PTR types like _workstation._tcp.local
}

func ScanIP(ip string, ports map[int]bool, timeout time.Duration) *DeviceAsset {
	targetAddr := fmt.Sprintf("%s:5353", ip)

	// Create UDP connection
	conn, err := net.DialTimeout("udp", targetAddr, timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	// Map to keep track of queried services to avoid loops
	queried := make(map[string]bool)

	// Store all received records
	records := make([]dns.RR, 0)
	var recordsMutex sync.Mutex

	// Helper to send query
	sendQuery := func(qName string, qType uint16) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(qName), qType)
		// Unicast response bit
		m.Question[0].Qclass = dns.ClassINET | 0x8000
		m.RecursionDesired = false
		b, err := m.Pack()
		if err == nil {
			conn.Write(b)
		}
	}

	// Start by querying services
	startQuery := "_services._dns-sd._udp.local."
	queried[startQuery] = true
	sendQuery(startQuery, dns.TypePTR)

	// In some cases, devices don't respond to _services.
	// So we proactively query some common ones as well to be sure.
	commonServices := []string{
		"_workstation._tcp.local.",
		"_http._tcp.local.",
		"_smb._tcp.local.",
		"_device-info._tcp.local.",
		"_qdiscover._tcp.local.",
		"_afpovertcp._tcp.local.",
	}
	for _, s := range commonServices {
		queried[s] = true
		sendQuery(s, dns.TypePTR)
	}

	buf := make([]byte, 4096)

	// Read loop
	for {
		n, err := conn.Read(buf)
		if err != nil {
			// Timeout or error
			break
		}

		msg := new(dns.Msg)
		err = msg.Unpack(buf[:n])
		if err != nil {
			continue
		}

		recordsMutex.Lock()
		records = append(records, msg.Answer...)
		records = append(records, msg.Extra...)
		recordsMutex.Unlock()

		// Check if we need to follow up
		for _, answer := range msg.Answer {
			if ptr, ok := answer.(*dns.PTR); ok {
				target := ptr.Ptr
				// If it's a service type (e.g., _http._tcp.local.)
				if strings.Contains(target, "._tcp.local.") || strings.Contains(target, "._udp.local.") {
					if !queried[target] {
						queried[target] = true
						sendQuery(target, dns.TypePTR)
					}
				}
			}
		}
	}

	if len(records) == 0 {
		return nil
	}

	return parseRecords(ip, records, ports)
}

func parseRecords(ip string, records []dns.RR, ports map[int]bool) *DeviceAsset {
	asset := &DeviceAsset{
		IP:      ip,
		Answers: make([]string, 0),
	}

	// Group records by instance name
	type instanceData struct {
		SRV         *dns.SRV
		TXT         *dns.TXT
		A           *dns.A
		AAAA        *dns.AAAA
		ServiceType string
	}

	instances := make(map[string]*instanceData)
	answersMap := make(map[string]bool)

	// First pass: collect PTRs
	for _, r := range records {
		if ptr, ok := r.(*dns.PTR); ok {
			// If it's a PTR for _services, it points to a service type
			if ptr.Hdr.Name == "_services._dns-sd._udp.local." {
				ans := strings.TrimSuffix(ptr.Ptr, ".")
				if !answersMap[ans] {
					answersMap[ans] = true
					asset.Answers = append(asset.Answers, ans)
				}
			} else {
				// It's a PTR for a service type, pointing to an instance
				// e.g. Name: _http._tcp.local. Ptr: slw-nas._http._tcp.local.
				instName := ptr.Ptr
				if instances[instName] == nil {
					instances[instName] = &instanceData{}
				}
				instances[instName].ServiceType = ptr.Hdr.Name

				ans := strings.TrimSuffix(ptr.Hdr.Name, ".")
				if !answersMap[ans] {
					answersMap[ans] = true
					asset.Answers = append(asset.Answers, ans)
				}
			}
		}
	}

	// Second pass: collect SRV, TXT
	for _, r := range records {
		switch v := r.(type) {
		case *dns.SRV:
			instName := v.Hdr.Name
			if instances[instName] == nil {
				instances[instName] = &instanceData{}
			}
			instances[instName].SRV = v
		case *dns.TXT:
			instName := v.Hdr.Name
			if instances[instName] == nil {
				instances[instName] = &instanceData{}
			}
			instances[instName].TXT = v
		}
	}

	// Third pass: collect A, AAAA based on SRV targets
	targetToA := make(map[string]string)
	targetToAAAA := make(map[string]string)
	for _, r := range records {
		switch v := r.(type) {
		case *dns.A:
			targetToA[v.Hdr.Name] = v.A.String()
		case *dns.AAAA:
			targetToAAAA[v.Hdr.Name] = v.AAAA.String()
		}
	}

	// Process instances
	for instName, data := range instances {
		if data.SRV == nil {
			continue
		}

		port := int(data.SRV.Port)
		// Filter by port
		if len(ports) > 0 && !ports[port] {
			continue
		}

		svcTypeRaw := data.ServiceType
		if svcTypeRaw == "" {
			// Try to extract from instance name
			// e.g., slw-nas._http._tcp.local.
			idx := strings.Index(instName, "._")
			if idx != -1 {
				svcTypeRaw = instName[idx+1:]
			}
		}

		svcType := ""
		proto := ""

		// Parse _http._tcp.local.
		parts := strings.Split(strings.TrimSuffix(svcTypeRaw, "."), ".")
		if len(parts) >= 2 {
			svcType = strings.TrimPrefix(parts[0], "_")
			proto = strings.TrimPrefix(parts[1], "_")
		}

		name := strings.TrimSuffix(instName, "."+svcTypeRaw)

		target := data.SRV.Target
		ipv4 := targetToA[target]
		ipv6 := targetToAAAA[target]

		if ipv4 == "" {
			ipv4 = ip // fallback to scanned IP
		}

		var txts []string
		if data.TXT != nil {
			txts = data.TXT.Txt
		}

		sa := ServiceAsset{
			ServiceType: svcType,
			Proto:       proto,
			Port:        port,
			Name:        name,
			IPv4:        ipv4,
			IPv6:        ipv6,
			Hostname:    strings.TrimSuffix(target, "."),
			TTL:         data.SRV.Hdr.Ttl,
			TXT:         txts,
		}

		if svcType == "device-info" {
			asset.DeviceInfo = &sa
		} else {
			asset.Services = append(asset.Services, sa)
		}
	}

	if len(asset.Services) == 0 && asset.DeviceInfo == nil {
		return nil
	}

	return asset
}
