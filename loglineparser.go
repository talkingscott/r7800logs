package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// The time zone in which R7800 logs are being produced
const homeTimeZone = "America/New_York"

// The date/time layout used in R7800 log messages
const timeLayout = "Monday, January 02, 2006 15:04:05"

var homeLocation *time.Location
var logLineRegExp *regexp.Regexp

func init() {
	var err error

	// R7800 log messages conform to this RE
	logLineRegExp, err = regexp.Compile("\\[(.+)\\](.+)((Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday).+)")
	if err != nil {
		log.Fatal(err)
	}

	homeLocation, err = time.LoadLocation(homeTimeZone)
	if err != nil {
		log.Fatal(err)
	}
}

// checkEvent just confirms that it knows about this kind of event
func checkEvent(event string) {
	if event == "LAN access from remote" {
		return
	}
	if event == "Internet connected" {
		return
	}
	if event == "DoS Attack: ACK Scan" {
		return
	}
	if event == "DoS Attack: ARP Attack" {
		return
	}
	if event == "DoS Attack: RST Scan" {
		return
	}
	if event == "DoS Attack: SYN/ACK Scan" {
		return
	}
	if event == "DoS Attack: TCP/UDP Chargen" {
		return
	}
	if event == "DoS Attack: UDP Port Scan" {
		return
	}
	if strings.HasPrefix(event, "DHCP IP: ") {
		return
	}
	if event == "Time synchronized with NTP server" {
		return
	}
	if strings.HasPrefix(event, "email sent to: ") {
		return
	}
	log.Fatal("Do not know event " + event)
}

// ParseLogLine parses a single R7800 log line.  For now it just flags things it doesn't
// understand/expect.
func ParseLogLine(logLine string) {
	//log.Println(logLine)

	matches := logLineRegExp.FindStringSubmatch(logLine)
	//log.Printf("Found %v matches", len(matches))
	if len(matches) != 5 {
		log.Printf("Expected 5 matches, got %v, in %v", len(matches), logLine)
		return
	}

	dt, err := time.ParseInLocation(timeLayout, matches[3], homeLocation)
	if err != nil {
		fmt.Printf("Error parsing %v: %v", matches[3], err)
	}

	event := matches[1]
	detail := matches[2]
	log.Println(dt, event, detail)

	checkEvent(event)
}
