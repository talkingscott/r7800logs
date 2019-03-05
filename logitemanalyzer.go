package main

import (
	"log"
	"regexp"
	"strings"
	"time"
)

var wanAddressRE *regexp.Regexp

var lanAddressEventRE *regexp.Regexp
var lanAddressDetailRE *regexp.Regexp

func init() {
	var err error

	wanAddressRE, err = regexp.Compile("IP address: (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})")
	if err != nil {
		log.Fatal("Unable to compile RE for WAN address")
	}

	lanAddressEventRE, err = regexp.Compile("DHCP IP: (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})")
	if err != nil {
		log.Fatal("Unable to compile RE for LAN address event")
	}

	lanAddressDetailRE, err = regexp.Compile("to MAC address ([0123456789abcdef:]+)")
	if err != nil {
		log.Fatal("Unable to compile RE for LAN address detail")
	}
}

// PrintLogItem prints the LogItem.
func PrintLogItem(logItem *LogItem) bool {
	log.Println(logItem.Instant, logItem.Event, logItem.Detail)
	return true
}

// CheckLogItem checks that it understands the LogItem.
func CheckLogItem(logItem *LogItem) bool {
	event := logItem.Event

	if event == "LAN access from remote" {
		// details includes remote and local addresses
		return true
	}
	if event == "Internet connected" {
		// details includes WAN IP address
		return true
	}
	if event == "DoS Attack: ACK Scan" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: ARP Attack" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: Ascend Kill" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: RST Scan" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: SYN/ACK Scan" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: TCP/UDP Chargen" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: TCP/UDP Echo" {
		// details includes remote address and event has attach type
		return true
	}
	if event == "DoS Attack: UDP Port Scan" {
		// details includes remote address and event has attach type
		return true
	}
	if strings.HasPrefix(event, "DHCP IP: ") {
		// details includes MAC address and event has LAN IP address
		return true
	}
	if event == "Time synchronized with NTP server" {
		// are there details?
		return true
	}
	if strings.HasPrefix(event, "email sent to: ") {
		// no details and event has e-mail address - this is really of no interest
		return true
	}
	log.Fatal("Do not know event " + event)

	return true
}

// WANAddress is the last tracked WAN address
var WANAddress string
var wanAddressInstant *time.Time

// TrackWANAddress tracks the IP address assigned to the WAN port.
func TrackWANAddress(logItem *LogItem) bool {
	if logItem.Event == "Internet connected" {
		if wanAddressInstant == nil || logItem.Instant.After(*wanAddressInstant) {
			matches := wanAddressRE.FindStringSubmatch(logItem.Detail)
			if len(matches) != 2 {
				log.Fatal("Expected 2 matches in " + logItem.Detail)
			}
			WANAddress = matches[1]
			wanAddressInstant = &logItem.Instant
		}
		return true
	}
	return false
}

// For now, don't store instants to compare

// LANAddressToMAC tracks MAC associated with each LAN address
var LANAddressToMAC = make(map[string]string)

// MACToLANAddress tracks IP address assigned to each MAC
var MACToLANAddress = make(map[string]string)

// TrackLANAddresses tracks the IP address assigned to LAN MACs.
func TrackLANAddresses(logItem *LogItem) bool {
	matches := lanAddressEventRE.FindStringSubmatch(logItem.Event)
	if len(matches) == 0 {
		return false
	}
	lanIPAddress := matches[1]
	matches = lanAddressDetailRE.FindStringSubmatch(logItem.Detail)
	if len(matches) != 2 {
		log.Fatal("Expected MAC address in " + logItem.Detail)
	}
	lanMACAddress := matches[1]

	// TODO: store and check instants
	LANAddressToMAC[lanIPAddress] = lanMACAddress
	MACToLANAddress[lanMACAddress] = lanIPAddress

	return true
}
