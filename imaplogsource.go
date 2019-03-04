package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
)

const r7800subject = "NETGEAR R7800 Log"

// ImapConfig is IMAP configuration for an IMAP log source
type ImapConfig struct {
	Server   string
	Username string
	Password string
}

// NewImapConfig creates new configuration from a JSON file
func NewImapConfig(filename string) (*ImapConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	conf := ImapConfig{}
	err = decoder.Decode(&conf)
	return &conf, err
}

// GetLogLines reads log lines from IMAP e-mail messages, sending them to the specified channel.
// This is adapted from go-imap examples.
// N.B. this currently calls log.Fatal on errors
func (conf *ImapConfig) GetLogLines(logLines chan string) {
	log.Println("Connecting to server...")

	c, err := client.DialTLS(conf.Server, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Logout()
	log.Println("Connected")

	if err := c.Login(conf.Username, conf.Password); err != nil {
		log.Fatal(err)
	}
	log.Println("Logged in")

	_, err = c.Select("INBOX", false)
	if err != nil {
		log.Fatal(err)
	}

	criteria := imap.NewSearchCriteria()
	criteria.Header.Add("SUBJECT", r7800subject)
	uids, err := c.Search(criteria)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Search returned %v uids", len(uids))

	if len(uids) > 0 {
		seqSet := new(imap.SeqSet)
		seqSet.AddNum(uids...)

		// Get the whole message body
		section := &imap.BodySectionName{}
		items := []imap.FetchItem{section.FetchItem()}

		messages := make(chan *imap.Message, 10)
		done := make(chan error, 1)
		go func() {
			done <- c.Fetch(seqSet, items, messages)
		}()

		log.Println("Read messages")
		for msg := range messages {

			r := msg.GetBody(section)
			if r == nil {
				log.Fatal("Server didn't returned message body")
			}

			mr, err := mail.CreateReader(r)
			if err != nil {
				log.Fatal(err)
			}

			header := mr.Header
			if date, err := header.Date(); err == nil {
				log.Println("Date:", date)
			}
			if from, err := header.AddressList("From"); err == nil {
				log.Println("From:", from)
			}
			if to, err := header.AddressList("To"); err == nil {
				log.Println("To:", to)
			}
			if subject, err := header.Subject(); err == nil {
				log.Println("Subject:", subject)
			}

			// Process each message part
			for {
				p, err := mr.NextPart()
				if err == io.EOF {
					break
				} else if err != nil {
					log.Fatal(err)
				}

				switch h := p.Header.(type) {
				case mail.TextHeader:
					// This is the message's text (can be plain-text or HTML)
					//b, _ := ioutil.ReadAll(p.Body)
					//log.Println("Got text: ", string(b))

					scanner := bufio.NewScanner(p.Body)
					for scanner.Scan() {
						logLines <- scanner.Text()
					}
					if err := scanner.Err(); err != nil {
						log.Fatal(err)
					}

				case mail.AttachmentHeader:
					// This is an attachment, which we do not expect!
					filename, _ := h.Filename()
					log.Println("Got attachment: ", filename)
				}
			}
		}
	}

	// N.B. the done channel should be read to detect errors, right?

	close(logLines)
}
