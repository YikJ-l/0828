package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseIPs parses CIDR, range, or single IP strings into a list of IPs.
func ParseIPs(input string) ([]string, error) {
	var ips []string
	if strings.Contains(input, "/") {
		// CIDR
		ip, ipnet, err := net.ParseCIDR(input)
		if err != nil {
			return nil, err
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
			ips = append(ips, ip.String())
		}
		// Remove network address and broadcast address if it's IPv4
		if len(ips) > 2 && ips[0] == ip.Mask(ipnet.Mask).String() {
			ips = ips[1 : len(ips)-1]
		}
		return ips, nil
	} else if strings.Contains(input, "-") {
		// Range
		parts := strings.Split(input, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range format")
		}
		startIP := net.ParseIP(parts[0])
		endIP := net.ParseIP(parts[1])
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IP addresses in range")
		}
		start := binary.BigEndian.Uint32(startIP.To4())
		end := binary.BigEndian.Uint32(endIP.To4())
		if start > end {
			return nil, fmt.Errorf("start IP is greater than end IP")
		}
		for i := start; i <= end; i++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)
			ips = append(ips, ip.String())
		}
		return ips, nil
	}
	// Single IP
	ip := net.ParseIP(input)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	return []string{ip.String()}, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParsePorts parses port strings (e.g., "80,443,1000-2000") into a map for fast lookup.
func ParsePorts(input string) (map[int]bool, error) {
	ports := make(map[int]bool)
	if input == "" {
		return ports, nil
	}
	parts := strings.Split(input, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			ranges := strings.Split(part, "-")
			if len(ranges) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err := strconv.Atoi(ranges[0])
			if err != nil {
				return nil, err
			}
			end, err := strconv.Atoi(ranges[1])
			if err != nil {
				return nil, err
			}
			for i := start; i <= end; i++ {
				ports[i] = true
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports[port] = true
		}
	}
	return ports, nil
}
