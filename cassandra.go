package main

import (
	"fmt"
	"log"
	"net"

	"github.com/gocql/gocql"
	"github.com/miekg/dns"
)

// CassandraDB : Implements DBDriver and holds the cassandra session
type CassandraDB struct {
	session *gocql.Session
}

// MakeQuery : using a valid session stored on CassandraDB makes a get
// query to the desired database
func (c *CassandraDB) MakeQuery(m *dns.Msg) {

	var dnsq dns.Question = m.Question[0]
	s := c.session

	switch dnsq.Qtype {
	case dns.TypeA:
		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var address string

		iter := s.Query(`SELECT * FROM domain_a WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &address, &class, &ttl) {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   net.ParseIP(address).To4(),
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeNS:

		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var nsdname string

		iter := s.Query(`SELECT * FROM domain_ns WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &class, &nsdname, &ttl) {
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
				Ns:  nsdname,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeCNAME:

		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var domainCname string

		iter := s.Query(`SELECT * FROM domain_cname WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &class, &domainCname, &ttl) {
			rr := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: domainName, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: domainCname,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeSOA:

		var domainName string
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
		for iter.Scan(&domainName, &id, &class, &expire, &minimum, &mname, &refresh, &retry, &rname, &serial, &ttl) {
			rr := &dns.SOA{
				Hdr:     dns.RR_Header{Name: domainName, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
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

		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var ptrdname string

		iter := s.Query(`SELECT * FROM domain_ptr WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &class, &ptrdname, &ttl) {
			rr := &dns.PTR{
				Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
				Ptr: ptrdname,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeHINFO:

		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var cpu string
		var os string

		iter := s.Query(`SELECT * FROM domain_hinfo WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &class, &cpu, &os, &ttl) {
			rr := &dns.HINFO{
				Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: ttl},
				Cpu: cpu,
				Os:  os,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeMX:

		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var preference uint16
		var exchange string

		iter := s.Query(`SELECT * FROM domain_mx WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &class, &exchange, &preference, &ttl) {
			rr := &dns.MX{
				Hdr:        dns.RR_Header{Name: domainName, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
				Preference: preference,
				Mx:         exchange,
			}
			m.Answer = append(m.Answer, rr)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		}
	case dns.TypeTXT:

		var domainName string
		var id gocql.UUID
		var class uint16
		var ttl uint32
		var current string
		var data []string

		// TXT records have a list of txt values but sharing ttl and other data
		iter := s.Query(`SELECT * FROM domain_txt WHERE domain_name = ?`, dnsq.Name).Iter()
		for iter.Scan(&domainName, &id, &class, &current, &ttl) {
			data = append(data, current)
		}
		if err := iter.Close(); err != nil {
			log.Fatal(err)
		} else {
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: data,
			}
			m.Answer = append(m.Answer, rr)
		}
	}
}

// Disconnect : ends the cassandra session
func (c *CassandraDB) Disconnect() {
	c.session.Close()
}

// ConnectDB : Starts a cassandra session to a cluster given the ips.
// If it fails it dies
func (c *CassandraDB) ConnectDB(ips []string) {
	cluster := gocql.NewCluster(ips...)
	cluster.Keyspace = "dns"
	cluster.Consistency = gocql.Quorum

	// Have one session to interact with the db using goroutines
	// The session executor launches a go routine to fetch the results
	session, err := cluster.CreateSession()
	if err != nil {
		log.Fatalf("Couldn't connect to Cassandra Cluster: %v", err)
	}
	c.session = session
}

// Handle : function to call on the dns server when a package is received.
// Prepares the package and calls Cassandra to fill it up
func (c *CassandraDB) Handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if *printf {
		fmt.Printf("%v\n", m.String())
	}

	c.MakeQuery(m)
	w.WriteMsg(m)
}
