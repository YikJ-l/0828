package main

import (
	"flag"
	"fmt"
	"strings"
	"sync"
	"time"
)

func main() {
	ipFlag := flag.String("ip", "", "Target IP range (e.g. 192.168.1.0/24 or 192.168.1.1-192.168.1.10)")
	portFlag := flag.String("p", "", "Target port range (e.g. 1-65535, 80,443)")
	flag.Parse()

	if *ipFlag == "" {
		fmt.Println("Usage: mdns-scanner -ip <ip_range> -p <port_range>")
		return
	}

	ips, err := ParseIPs(*ipFlag)
	if err != nil {
		fmt.Printf("Error parsing IP: %v\n", err)
		return
	}

	ports, err := ParsePorts(*portFlag)
	if err != nil {
		fmt.Printf("Error parsing Ports: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	results := make(chan *DeviceAsset, len(ips))

	// Limit concurrency
	sem := make(chan struct{}, 100)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			
			// 2 seconds timeout for UDP collection
			asset := ScanIP(target, ports, 2*time.Second)
			if asset != nil {
				results <- asset
			}
		}(ip)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Output format
	for asset := range results {
		if len(asset.Services) > 0 {
			fmt.Println("services:")
			for _, svc := range asset.Services {
				fmt.Printf("%d/%s %s:\n", svc.Port, svc.Proto, svc.ServiceType)
				fmt.Printf("Name=%s\n", svc.Name)
				fmt.Printf("IPv4=%s\n", svc.IPv4)
				if svc.IPv6 != "" {
					fmt.Printf("IPv6=%s\n", svc.IPv6)
				}
				fmt.Printf("Hostname=%s\n", svc.Hostname)
				fmt.Printf("TTL=%d\n", svc.TTL)
				
				// Print TXT records
				if len(svc.TXT) > 0 {
					fmt.Println(strings.Join(svc.TXT, ","))
				}
			}
		}

		if asset.DeviceInfo != nil {
			fmt.Println("device-info:")
			fmt.Printf("Name=%s\n", asset.DeviceInfo.Name)
			fmt.Printf("IPv4=%s\n", asset.DeviceInfo.IPv4)
			if asset.DeviceInfo.IPv6 != "" {
				fmt.Printf("IPv6=%s\n", asset.DeviceInfo.IPv6)
			}
			fmt.Printf("Hostname=%s\n", asset.DeviceInfo.Hostname)
			fmt.Printf("TTL=%d\n", asset.DeviceInfo.TTL)
			
			if len(asset.DeviceInfo.TXT) > 0 {
				for _, txt := range asset.DeviceInfo.TXT {
					fmt.Println(txt)
				}
			}
		}

		if len(asset.Answers) > 0 {
			fmt.Println("answers:")
			fmt.Println("PTR:")
			for _, ans := range asset.Answers {
				fmt.Println(ans)
			}
		}
	}
}
