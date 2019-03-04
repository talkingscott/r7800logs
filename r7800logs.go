package main

import (
	"log"
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
		ParseLogLine(logLine)
	}
}
