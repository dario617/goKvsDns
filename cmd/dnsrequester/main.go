// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Q is a small utility which acts and behaves like 'dig' from BIND.
// It is meant to stay lean and mean, while having a bunch of handy
// features, like -check which checks if a packet is correctly signed (without
// checking the chain of trust).
// When using -check a comment is printed:
//
// ;+ Secure signature, miek.nl. RRSIG(SOA) validates (DNSKEY miek.nl./4155/net)
//
// which says the SOA has a valid RRSIG and it validated with the DNSKEY of miek.nl,
// which has key id 4155 and is retrieved from the server. Other values are 'disk'.
package dnsrequester

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// TODO(miek): serial in ixfr

var (
	query        = flag.Bool("question", false, "show question")
	port         = flag.Int("port", 53, "port number to use")
	aa           = flag.Bool("aa", false, "set AA flag in query")
	ad           = flag.Bool("ad", false, "set AD flag in query")
	cd           = flag.Bool("cd", false, "set CD flag in query")
	rd           = flag.Bool("rd", true, "set RD flag in query")
	fallback     = flag.Bool("fallback", false, "fallback to 4096 bytes bufsize and after that TCP")
	timeoutDial  = flag.Duration("timeout-dial", 2*time.Second, "Dial timeout")
	timeoutRead  = flag.Duration("timeout-read", 2*time.Second, "Read timeout")
	timeoutWrite = flag.Duration("timeout-write", 2*time.Second, "Write timeout")
	opcode       = flag.String("opcode", "query", "set opcode to query|update|notify")
	rcode        = flag.String("rcode", "success", "set rcode to noerror|formerr|nxdomain|servfail|...")
	outDir       = flag.String("outDir", "/home/andhael/SE/memoria/GoDNSServer/output.txt", "output text file")
	dir          = flag.String("dir", "/home/andhael/SE/memoria/GoDNSServer/data/sorted/", "caida ips and domains files text file")
	routines     = flag.Int("routines", 3, "routines to conduct paralel queries")
	startFrom    = flag.Int("startFrom", 0, "start at line")
	cores        = flag.Int("cores", 1, "parallel cores")
	skip         = flag.Int("skip", 0, "Skip every n lines")
)

func makeRequests(c, o chan string, nameserver []string) {

	// Client to make the requests
	client := new(dns.Client)
	client.DialTimeout = *timeoutDial
	client.ReadTimeout = *timeoutRead
	client.WriteTimeout = *timeoutWrite

	const qc = uint16(dns.ClassINET)

	// Types for queries
	var qtypes = []uint16{dns.TypeMX, dns.TypeCNAME, dns.TypeA,
		dns.TypeHINFO, dns.TypeNS, dns.TypeSOA, dns.TypeTXT}

	// Create the msg
	message := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     *aa,
			AuthenticatedData: *ad,
			CheckingDisabled:  *cd,
			RecursionDesired:  *rd,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}

	var chosenNSindex int = 0
	var tries int = 0

	// Process
	for {
		domain, ok := <-c
		if ok == false {
			fmt.Println("Channel Close ", ok)
			break
		}

		for _, qt := range qtypes {

			// Set UDP mode always
			client.Net = "udp"

			// Set the RR in the question
			message.Question[0] = dns.Question{Name: dns.Fqdn(domain), Qtype: uint16(qt), Qclass: qc}
			message.Id = dns.Id()

			tries = 0

		Redo:
			// Send the request
			response, rtt, err := client.Exchange(message, nameserver[chosenNSindex])
			tries++

			switch err {
			case nil:
				//do nothing
			default:
				fmt.Printf("%s ;; %s try/%d\n", err.Error(), domain, tries)

				if tries >= 4 {
					fmt.Printf("\n\nAborted for %s, %d\n\n", domain, qt)
					continue
				}
				// If timeout ocurred retry on next NS
				if e := err.Error(); strings.Contains(e, "i/o timeout") {
					chosenNSindex = (chosenNSindex + 1) % len(nameserver)
					fmt.Printf("Triying ... %s\n", nameserver[chosenNSindex])
					goto Redo
				} else {
					continue
				}
			}
			if response.Truncated {
				if *fallback {
					// First EDNS, then TCP
					fmt.Printf(";; Truncated, trying TCP\n")
					client.Net = "tcp"
					*fallback = false
					goto Redo
				}
				fmt.Printf(";; Truncated\n")
			}

			if response.Id != message.Id {
				fmt.Fprintf(os.Stderr, "Id mismatch\n")
				goto Redo
			}
			if len(response.Answer) > 0 {
				fmt.Printf("Domain %s, Duration: %v, Type %v, Answers %v\n", domain, rtt, qt, len(response.Answer))
				for _, ans := range response.Answer {
					o <- ans.String()
				}
			}
		}
	}
}

func writeResultsToFile(c chan string, filename string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't open the file %s", filename)
		os.Exit(3)
	}
	defer f.Close()

	for {
		line := <-c
		_, err := f.WriteString(line + "\n")
		if err != nil {
			break
		}
	}
}

func parseNameServer() []string {
	var nameservers []string
	for _, arg := range flag.Args() {
		// If it starts with @ it is a nameserver
		if arg[0] == '@' {
			nameservers = append(nameservers, string([]byte(arg)[1:])) // chop off @
			continue
		}
	}

	if len(nameservers) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for _, v := range conf.Servers {
			nameservers = append(nameservers, v)
		}
	}

	// if the nameserver is from /etc/resolv.conf the [ and ] are already
	// added, thereby breaking net.ParseIP. Check for this and don't
	// fully qualify such a name
	for i, v := range nameservers {
		if v[0] == '[' && v[len(v)-1] == ']' {
			nameservers[i] = v[1 : len(v)-1]
		}
	}
	for i, v := range nameservers {
		if j := net.ParseIP(v); j != nil {
			nameservers[i] = net.JoinHostPort(v, strconv.Itoa(*port))
		} else {
			nameservers[i] = dns.Fqdn(v) + ":" + strconv.Itoa(*port)
		}
	}
	return nameservers
}

func main() {

	runtime.GOMAXPROCS(*cores)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [@server] [qtype...] [qclass...] [name ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// Recover custom nameserver
	var nameservers []string = parseNameServer()

	// Read files and return if failed
	files, err := ioutil.ReadDir(*dir)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// Prepare routines for dns msg exchange and writing
	channel := make(chan string, *routines)
	output_chan := make(chan string, *routines*2)
	go writeResultsToFile(output_chan, *outDir)
	for i := 0; i < *routines; i++ {
		go makeRequests(channel, output_chan, nameservers)
	}

	for _, f := range files {
		file, err := os.Open(*dir + f.Name())

		defer file.Close()

		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)

		var counter float64 = 0

		// Move our pointer forward
		if *startFrom != 0 {
			for scanner.Scan() {
				counter++
				if int(counter) >= *startFrom {
					break
				}
			}
		}

		for scanner.Scan() {
			// Send text to our resolver and recover the answers
			counter++
			if *skip != 0 && int(counter)%*skip == 0 {
				a := scanner.Text()
				fmt.Printf("%f line %d- Doing %s\n", counter*100/71488071.0, int(counter), a)
				channel <- a
			}
		}
		fmt.Printf("Last line read: %d %s", int(counter), scanner.Text())
	}

	fmt.Printf("\n\nFinished file processing, awaiting responses / user termination\n\n")

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)

}
