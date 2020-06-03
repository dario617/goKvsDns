package server

import (
	"log"
	"net"
	"strings"

	"github.com/gocql/gocql"
	"github.com/miekg/dns"
)

// CassandraDB : Implements DBDriver and holds the cassandra session
type CassandraDB struct {
	session *gocql.Session
	Print   bool
}

// MakeQuery : using a valid session stored on CassandraDB makes a get
// query to the desired database
func (c *CassandraDB) MakeQuery(m *dns.Msg) int {

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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
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
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: domainName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: data,
		}
		m.Answer = append(m.Answer, rr)
		if err := iter.Close(); err != nil {
			log.Printf("Error on Cassandra %v", err)
			return 2 // Server Problem
		}
	}
	if len(m.Answer) >= 1 {
		return 0 // No error
	}
	return 3 // Domain name does not exists
}

// UploadRR to Cassandra Cluster from line
func (c *CassandraDB) UploadRR(line string) error {

	var values = map[string]int{
		"IN": 1,
	}

	s := c.session
	// Capture tokens
	tk := strings.Split(line, "\t")
	var dnsType string = tk[3]

	switch dnsType {
	case "A":
		if err := s.Query(`INSERT INTO domain_a (domain_name, id, class, ttl, address) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading A %s", tk)
				return err
				// Retry
			}
		}
	case "NS":
		if err := s.Query(`INSERT INTO domain_ns (domain_name, id, class, ttl, nsdname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				// Retry
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading NS %s", tk)
				return err
			}
		}
	case "CNAME":
		if err := s.Query(`INSERT INTO domain_cname (domain_name, id, class, ttl, domain_cname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading CNAME %s", tk)
				return err
				// Retry
			}
		}
	case "SOA":
		soaData := strings.Split(tk[4], " ")
		if err := s.Query(`INSERT INTO domain_soa (domain_name, id, class, ttl, mname, rname, serial, refresh, retry, expire, minimum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], soaData[0], soaData[1], soaData[2], soaData[3], soaData[4], soaData[5], soaData[6]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading SOA %s", tk)
				return err
				// Retry
			}
		}
	case "PTR":
		// Check that domain name is in-addr.arpa compliant
		// Just in case the record was added as an IP and answer
		var domain string = tk[0]
		if strings.Contains(domain, "in-addr.arpa") {
			domain, _ = dns.ReverseAddr(domain)
		}
		if err := s.Query(`INSERT INTO domain_ptr (domain_name, id, class, ttl, ptrdname) VALUES (?, ?, ?, ?, ?)`,
			domain, gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading PTR %s", tk)
				return err
				// Retry
			}
		}
	case "HINFO":
		hinfoData := strings.Split(tk[4], " ")
		if err := s.Query(`INSERT INTO domain_hinfo (domain_name, id, class, ttl, cpu, os) VALUES (?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], hinfoData[0], hinfoData[1]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading HINFO %s", tk)
				return err
				// Retry
			}
		}
	case "MX":
		mxData := strings.Split(tk[4], " ")
		if err := s.Query(`INSERT INTO domain_mx (domain_name, id, class, ttl, preference, exchange) VALUES (?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], mxData[0], mxData[1]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading MX %s", tk)
				return err
				// Retry
			}
		}
	case "TXT":
		if err := s.Query(`INSERT INTO domain_txt (domain_name, id, class, ttl, txt) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], strings.ReplaceAll(tk[4], "\"", "")).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				c.UploadRR(line)
			} else {
				log.Printf("Error uploading TXT %s", tk)
				return err
				// Retry
			}
		}
	}
	return nil
}

// HandleFile reads a file containing RRs a uploads them replacing if set
func (c *CassandraDB) HandleFile(location string, replace bool) {
	log.Println("Not implemented")
	return
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

	if c.print {
		logQuery(r)
	}

	if r.MsgHdr.Authoritative {
		m.MsgHdr.Rcode = 4 // Not implemented
		w.WriteMsg(m)
	} else {
		rcode := c.MakeQuery(m)
		m.MsgHdr.Rcode = rcode
		w.WriteMsg(m)
	}
}
