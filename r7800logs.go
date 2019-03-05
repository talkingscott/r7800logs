package main

import (
	"log"
	"sort"
)

const imapConfigFile = "conf.json"

func main() {
	conf, err := NewImapConfig(imapConfigFile)
	if err != nil {
		log.Fatal(err)
	}

	logLines := make(chan string, 10)

	go conf.GetLogLines(logLines)

	for logLine := range logLines {
		// we want to parse to receive a parsed line and hand that to an aggregator/accumulator/processor/analyzer
		// one processor may track the WAN address
		// one processor may track LAN addresses
		// one processor may track DoS attacks
		// one processor may track attacks on ssh port
		logItem := ParseLogLine(logLine)
		PrintLogItem(logItem)
		CheckLogItem(logItem)
		TrackWANAddress(logItem)
		TrackLANAddresses(logItem)
	}

	log.Printf("WAN Address: %v", WANAddress)

	var ips []string
	for ip := range LANAddressToMAC {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		log.Printf("LAN %v: %v", ip, LANAddressToMAC[ip])
	}
}
