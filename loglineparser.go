package main

import (
	"fmt"
	"log"
	"regexp"
	"time"
)

// The time zone in which R7800 logs are being produced
const homeTimeZone = "America/New_York"

// The date/time layout used in R7800 log messages
const timeLayout = "Monday, January 02, 2006 15:04:05"

var homeLocation *time.Location
var logLineRegExp *regexp.Regexp

// LogItem represents a single log message.
type LogItem struct {
	Event   string
	Detail  string
	Instant time.Time
}

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

// ParseLogLine parses a single R7800 log line.  For now it just flags things it doesn't
// understand/expect.
func ParseLogLine(logLine string) *LogItem {
	//log.Println(logLine)

	matches := logLineRegExp.FindStringSubmatch(logLine)
	//log.Printf("Found %v matches", len(matches))
	if len(matches) != 5 {
		log.Printf("Expected 5 matches, got %v, in %v", len(matches), logLine)
		return nil
	}

	dt, err := time.ParseInLocation(timeLayout, matches[3], homeLocation)
	if err != nil {
		fmt.Printf("Error parsing %v: %v", matches[3], err)
	}

	return &LogItem{Event: matches[1], Detail: matches[2], Instant: dt}
}
