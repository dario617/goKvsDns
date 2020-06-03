package server

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.etcd.io/etcd/clientv3"
)

// EtcdDB : Implements DBDriver and holds the etcd client
type EtcdDB struct {
	client  *clientv3.Client
	Timeout time.Duration
	Print   bool
}

// Disconnect : Closes the Ectd client
func (edb *EtcdDB) Disconnect() {
	edb.client.Close()
}

// ConnectDB : assign etcd cluster client given the IPs and ports
func (edb *EtcdDB) ConnectDB(ips []string) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   ips,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Error while connecting to Etcd cluster %v", err)
	}
	edb.client = cli
}

// RecoverKey  from Etcd cluster using a timeout
func (edb *EtcdDB) RecoverKey(key string) (string, error) {
	cli := edb.client
	requestTimeout := edb.timeout
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	resp, err := cli.Get(ctx, key)
	cancel()

	if err != nil {
		return "", err
	}

	return string(resp.Kvs[0].Value), nil
}

// PutValueOnSet checks if value is present on set (a line). If not then it adds it
func (edb *EtcdDB) PutValueOnSet(key, value string) error {
	// Recover full value
	resp, err := edb.RecoverKey(key)
	if err != nil {
		return err
	}

	records := strings.Split(resp, ",")
	// Check that we are not repeating our selves
	var repeated bool = false
	for i := range records {
		if records[i] == value {
			repeated = true
		}
	}
	// Create new answer set
	if !repeated {
		newValue := resp + "," + value
		cli := edb.client
		requestTimeout := edb.timeout
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err = cli.Put(ctx, key, newValue)
		cancel()
		if err != nil {
			return err
		}
	}

	return nil
}

// MakeQuery : using a valid Etcd Client
// makes a get query
//
// Records will be in format
// DomainName:Type "TTL VALUES,TTL VALUES..."
func (edb *EtcdDB) MakeQuery(m *dns.Msg) int {

	var dnsq dns.Question = m.Question[0]

	switch dnsq.Qtype {
	case dns.TypeA:
		resp, err := edb.RecoverKey(dnsq.Name + ":A")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		records := strings.Split(resp, ",")
		for i := range records {
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
				A:   net.ParseIP(values[1]).To4(),
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeNS:
		resp, err := edb.RecoverKey(dnsq.Name + ":NS")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL NSDNAME
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Ns:  values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeCNAME:
		resp, err := edb.RecoverKey(dnsq.Name + ":CNAME")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL DOMAIN_NAME
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Target: values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeSOA:
		resp, err := edb.RecoverKey(dnsq.Name + ":SOA")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		values := strings.Split(resp, " ")
		// ttl mname rname serial refresh retry expire minimum
		ttl, _ := strconv.Atoi(values[0])
		serial, _ := strconv.Atoi(values[3])
		refresh, _ := strconv.Atoi(values[4])
		retry, _ := strconv.Atoi(values[5])
		expire, _ := strconv.Atoi(values[6])
		mintll, _ := strconv.Atoi(values[7])
		rr := &dns.SOA{
			Hdr:     dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Ns:      values[1],
			Mbox:    values[2],
			Serial:  uint32(serial),
			Refresh: uint32(refresh),
			Retry:   uint32(retry),
			Expire:  uint32(expire),
			Minttl:  uint32(mintll)}
		m.Answer = append(m.Answer, rr)
	case dns.TypePTR:
		resp, err := edb.RecoverKey(dnsq.Name + ":PTR")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL PTRDNAME
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.PTR{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Ptr: values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeHINFO:
		resp, err := edb.RecoverKey(dnsq.Name + ":HINFO")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL CPU OS
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.HINFO{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Cpu: values[1],
				Os:  values[2],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeMX:
		resp, err := edb.RecoverKey(dnsq.Name + ":MX")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL preference exchange
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			preference, _ := strconv.Atoi(values[1])
			rr := &dns.MX{
				Hdr:        dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Preference: uint16(preference),
				Mx:         values[2],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeTXT:
		resp, err := edb.RecoverKey(dnsq.Name + ":SOA")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		// TTL val1 val2 val3 ...
		records := strings.Split(resp, ",")
		ttl, _ := strconv.Atoi(records[0])
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Txt: records[1:],
		}
		m.Answer = append(m.Answer, rr)
	}

	if len(m.Answer) >= 1 {
		return 0 // No error
	}
	return 3 // Domain name does not exists
}

// UploadRR to Etcd Cluster from line appending it to the end of the value
func (edb *EtcdDB) UploadRR(line string) error {

	tk := strings.Split(line, "\t")
	var dnsType string = tk[3]

	switch dnsType {
	case "A":
		var key string = tk[0] + ":A"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.PutValueOnSet(key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "NS":
		var key string = tk[0] + ":NS"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.PutValueOnSet(key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "CNAME":
		var key string = tk[0] + ":CNAME"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.PutValueOnSet(key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "SOA":
		var key string = tk[0] + ":SOA"
		newValue := tk[1] + " " + tk[4]
		cli := edb.client
		requestTimeout := edb.timeout
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err := cli.Put(ctx, key, newValue)
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "PRT":
		// Check that domain name is in-addr.arpa compliant
		// Just in case the record was added as an IP and answer
		var domain string = tk[0]
		if strings.Contains(domain, "in-addr.arpa") {
			domain, _ = dns.ReverseAddr(domain)
		}
		var key string = domain + ":PTR"
		newValue := tk[1] + " " + tk[4]
		cli := edb.client
		requestTimeout := edb.timeout
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err := cli.Put(ctx, key, newValue)
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "HINFO":
		var key string = tk[0] + ":HINFO"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.PutValueOnSet(key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "MX":
		var key string = tk[0] + ":HINFO"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.PutValueOnSet(key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "TXT":
		var key string = tk[0] + ":TXT"
		var newRR string = tk[1] + " " + strings.ReplaceAll(tk[4], "\"", "")

		err := edb.PutValueOnSet(key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	}
	return nil
}

// HandleFile reads a file containing RRs a uploads them replacing if set
func (edb *EtcdDB) HandleFile(location string, replace bool) {
	log.Println("Not implemented")
	return
}

// Handle : function to call on the dns server when a package is received.
// Prepares the package and calls Etcd to fill it up
func (edb *EtcdDB) Handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if edb.print {
		logQuery(r)
	}

	if r.MsgHdr.Authoritative {
		m.MsgHdr.Rcode = 4 // Not implemented
		w.WriteMsg(m)
	} else {
		rcode := edb.MakeQuery(m)
		m.MsgHdr.Rcode = rcode
		w.WriteMsg(m)
	}
}
