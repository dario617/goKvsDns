// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reflect is a small name server which sends back the IP address of its client, the
// recursive resolver.
// When queried for type A (resp. AAAA), it sends back the IPv4 (resp. v6) address.
// In the additional section the port number and transport are shown.
//
// Basic use pattern:
//
//	dig @localhost -p 8053 whoami.miek.nl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;whoami.miek.nl.			IN	A
//
//	;; ANSWER SECTION:
//	whoami.miek.nl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	whoami.miek.nl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Similar services: whoami.ultradns.net, whoami.akamai.net. Also (but it
// is not their normal goal): rs.dns-oarc.net, porttest.dns-oarc.net,
// amiopen.openresolvers.org.
//
// Original version is from: Stephane Bortzmeyer <stephane+grong@bortzmeyer.org>.
//
// Adapted to Go (i.e. completely rewritten) by Miek Gieben <miek@miek.nl>.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/gocql/gocql"
	"github.com/miekg/dns"
)

var (
	cpuprofile  = flag.String("cpuprofile", "", "write cpu profile to file")
	printf      = flag.Bool("print", false, "print replies")
	compress    = flag.Bool("compress", false, "compress replies")
	soreuseport = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu         = flag.Int("cpu", 0, "number of cpu to use")
	db          = flag.String("db", "cassandra", "db to connect: cassandra|redis|pebble")
	clusterIPs  = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
	conf        = flag.String("conf", "./conf/conf.yml", "configuration file")
)

// Make a query to the database and
// store the results on the Msg
func makeQuery(s *gocql.Session, m *dns.Msg) {

	var dnsq dns.Question = m.Question[0]

	switch dnsq.Qtype {
	case dns.TypeA:
		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var address string

		iter := s.Query(`SELECT * FROM domain_a WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &address) {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain_name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP(address).To4(),
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeNS:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var nsdname string

		iter := s.Query(`SELECT * FROM domain_ns WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &nsdname) {
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: domain_name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
				Ns:  nsdname,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeCNAME:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var domain_cname string

		iter := s.Query(`SELECT * FROM domain_cname WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &domain_cname) {
			rr := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: domain_name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: domain_cname,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeSOA:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var mname string
		var rname string
		var serial uint32
		var refresh uint32
		var retry uint32
		var expire uint32
		var minimum uint32

		iter := s.Query(`SELECT * FROM domain_soa WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &mname, &rname, &serial, &refresh, &retry, &expire, &minimum) {
			rr := &dns.SOA{
				Hdr:     dns.RR_Header{Name: domain_name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
				Ns:      mname,
				Mbox:    rname,
				Serial:  serial,
				Refresh: refresh,
				Retry:   retry,
				Expire:  expire,
				Minttl:  minimum}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypePTR:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var ptrdname string

		iter := s.Query(`SELECT * FROM domain_ptr WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &ptrdname) {
			rr := &dns.PTR{
				Hdr: dns.RR_Header{Name: domain_name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
				Ptr: ptrdname,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeHINFO:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var cpu string
		var os string

		iter := s.Query(`SELECT * FROM domain_hinfo WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &cpu, &os) {
			rr := &dns.HINFO{
				Hdr: dns.RR_Header{Name: domain_name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: ttl},
				Cpu: cpu,
				Os:  os,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeMX:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var preference uint16
		var exchange string

		iter := s.Query(`SELECT * FROM domain_mx WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &preference, &exchange) {
			rr := &dns.MX{
				Hdr:        dns.RR_Header{Name: domain_name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
				Preference: preference,
				Mx:         exchange,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeTXT:

		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var current string
		var data []string

		// TXT records have a list of txt values but sharing ttl and other data
		iter := s.Query(`SELECT * FROM domain_txt WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &class, &ttl, &current) {
			data = append(data, current)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		} else {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: domain_name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: data,
			}
			m.Answer = append(m.Answer, rr)
		}
	}
}

func disconnectCassandra(s *gocql.Session) {
	s.Close()
}

// Cassandra
func connectToCassandra() *gocql.Session {
	var ips []string = strings.Split(*clusterIPs, ",")
	cluster := gocql.NewCluster(ips...)
	cluster.Keyspace = "dns"
	cluster.Consistency = gocql.Quorum

	// Have one session to interact with the db using goroutines
	// The session executor launches a go routine to fetch the results
	session, _ := cluster.CreateSession()
	return session
}

func handleCassandra(w dns.ResponseWriter, r *dns.Msg, s *gocql.Session) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress

	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	// set TC when question is tc.miek.nl.
	if m.Question[0].Name == "tc.miek.nl." {
		m.Truncated = true
		// send half a message
		buf, _ := m.Pack()
		w.Write(buf[:len(buf)/2])
		return
	}

	makeQuery(s, m)

	w.WriteMsg(m)
}

func serve(net, name, secret string, soreuseport bool) {
	server := &dns.Server{Addr: "[::]:8053", Net: net, TsigSecret: nil, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		fmt.Printf("Failed to setup the "+net+" server: %s\n", err.Error())

	}
}

func main() {
	var name, secret string
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *cpu != 0 {
		runtime.GOMAXPROCS(*cpu)
	}

	// Connect to db
	switch *db {
	case "cassandra":
		session := connectToCassandra()
		dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			handleCassandra(w, r, session)
		})
		defer disconnectCassandra(session)
	case "redis":
		log.Fatal("Not yet implemented")
		return
	case "pebble":
		log.Fatal("Not yet implemented")
		return
	}

	if *soreuseport > 0 {
		for i := 0; i < *soreuseport; i++ {
			go serve("tcp", name, secret, true)
			go serve("udp", name, secret, true)
		}
	} else {
		go serve("tcp", name, secret, false)
		go serve("udp", name, secret, false)
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
