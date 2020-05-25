package main

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
	timeout time.Duration
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

// MakeQuery : using a valid Etcd Client
// makes a get query
//
// Records will be in format
// DomainName:Type "TTL VALUES,TTL VALUES..."
func (edb *EtcdDB) MakeQuery(m *dns.Msg) int {

	log.Printf("Hola 2")
	cli := edb.client
	requestTimeout := edb.timeout
	var dnsq dns.Question = m.Question[0]
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)

	switch dnsq.Qtype {
	case dns.TypeA:
		resp, err := cli.Get(ctx, dnsq.Name+":A")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			records := strings.Split(string(ev.Value), ",")
			for i := range records {
				values := strings.Split(records[i], " ")
				ttl, _ := strconv.Atoi(values[0])
				rr := &dns.A{
					Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
					A:   net.ParseIP(values[1]).To4(),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	case dns.TypeNS:
		resp, err := cli.Get(ctx, dnsq.Name+":NS")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			records := strings.Split(string(ev.Value), ",")
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
		}
	case dns.TypeCNAME:
		resp, err := cli.Get(ctx, dnsq.Name+":CNAME")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			records := strings.Split(string(ev.Value), ",")
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
		}
	case dns.TypeSOA:
		resp, err := cli.Get(ctx, dnsq.Name+":SOA")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			values := strings.Split(string(ev.Value), " ")
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
		}
	case dns.TypePTR:
		resp, err := cli.Get(ctx, dnsq.Name+":PTR")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			records := strings.Split(string(ev.Value), ",")
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
		}
	case dns.TypeHINFO:
		resp, err := cli.Get(ctx, dnsq.Name+":HINFO")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			records := strings.Split(string(ev.Value), ",")
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
		}
	case dns.TypeMX:
		resp, err := cli.Get(ctx, dnsq.Name+":MX")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			records := strings.Split(string(ev.Value), ",")
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
		}
	case dns.TypeTXT:
		resp, err := cli.Get(ctx, dnsq.Name+":TXT")
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		for _, ev := range resp.Kvs {
			// TTL val1 val2 val3 ...
			records := strings.Split(string(ev.Value), " ")
			ttl, _ := strconv.Atoi(records[0])
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Txt: records[1:],
			}
			m.Answer = append(m.Answer, rr)
		}
	default:
		cancel()
	}

	if len(m.Answer) >= 1 {
		return 0 // No error
	}
	return 3 // Domain name does not exists
}

// Handle : function to call on the dns server when a package is received.
// Prepares the package and calls Etcd to fill it up
func (edb *EtcdDB) Handle(w dns.ResponseWriter, r *dns.Msg) {
	log.Println("Hola 3 handle")
	m := new(dns.Msg)
	m.SetReply(r)

	if *printf {
		logQuery(r)
	}

	if r.MsgHdr.Authoritative {
		rcode := edb.MakeQuery(m)
		m.MsgHdr.Rcode = rcode
		w.WriteMsg(m)
	} else {
		m.MsgHdr.Rcode = 4 // Not implemented
		w.WriteMsg(m)
	}
}
