package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/gocql/gocql"
	"github.com/miekg/dns"
)

func makeQueryCassandra(s *gocql.Session, m *dns.Msg) {

	var dnsq dns.Question = m.Question[0]

	switch dnsq.Qtype {
	case dns.TypeA:
		var domain_name string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var address string

		iter := s.Query(`SELECT * FROM domain_a WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domain_name, &id, &address, &class, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &nsdname, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &domain_cname, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &expire, &minimum, &mname, &refresh, &retry, &rname, &serial, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &ptrdname, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &cpu, &os, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &exchange, &preference, &ttl) {
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
		for iter.Scan(&domain_name, &id, &class, &current, &ttl) {
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
	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatal("Couldn't connect to Cassandra Cluster")
	}
	return session
}

func handleCassandra(w dns.ResponseWriter, r *dns.Msg, s *gocql.Session) {
	m := new(dns.Msg)
	m.SetReply(r)

	if *printf {
		fmt.Printf("%v\n", m.String())
	}

	makeQueryCassandra(s, m)
	w.WriteMsg(m)
}
