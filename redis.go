package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/go-redis/redis"
	"github.com/miekg/dns"
)

// RedisKVS : Implements DBDriver and holds the redis cluster client
type RedisKVS struct {
	client *redis.ClusterClient
}

// MakeQuery : using a valid Redis client
// makes a get query
func (r *RedisKVS) MakeQuery(m *dns.Msg) int {
	var dnsq dns.Question = m.Question[0]
	rclient := r.client
	switch dnsq.Qtype {
	case dns.TypeA:

		rrVal, err := rclient.SMembers(dnsq.Name + ":A").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			for i := range rrVal {
				// TTL ADDRESS
				values := strings.Split(rrVal[i], " ")
				ttl, _ := strconv.Atoi(values[0])
				rr := &dns.A{
					Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
					A:   net.ParseIP(values[1]).To4(),
				}
				m.Answer = append(m.Answer, rr)
			}
		}

	case dns.TypeNS:

		rrVal, err := rclient.SMembers(dnsq.Name + ":NS").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			for i := range rrVal {
				// TTL NSDNAME
				values := strings.Split(rrVal[i], " ")
				ttl, _ := strconv.Atoi(values[0])
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)},
					Ns:  values[1],
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	case dns.TypeCNAME:

		rrVal, err := rclient.SMembers(dnsq.Name + ":CNAME").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			for i := range rrVal {
				// TTL DOMAIN_NAME
				values := strings.Split(rrVal[i], " ")
				ttl, _ := strconv.Atoi(values[0])
				rr := &dns.CNAME{
					Hdr:    dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: uint32(ttl)},
					Target: values[1],
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	case dns.TypeSOA:

		rrVal, err := rclient.Get(dnsq.Name + ":SOA").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			// ttl mname rname serial refresh retry expire minimum
			values := strings.Split(rrVal, " ")
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

		rrVal, err := rclient.Get(dnsq.Name + ":PTR").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			// TTL PTRDNAME
			values := strings.Split(rrVal, " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.PTR{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Ptr: values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeHINFO:

		rrVal, err := rclient.SMembers(dnsq.Name + ":HINFO").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			for i := range rrVal {
				// TTL CPU OS
				values := strings.Split(rrVal[i], " ")
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

		rrVal, err := rclient.SMembers(dnsq.Name + ":MX").Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			for i := range rrVal {
				// TTL preference exchange
				values := strings.Split(rrVal[i], " ")
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
		// TTL val1 val2 val3 ...
		rrVal, err := rclient.LRange(dnsq.Name+":TXT", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		} else {
			ttl, _ := strconv.Atoi(rrVal[0])
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Txt: rrVal[1:],
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	if len(m.Answer) >= 1 {
		return 0 // No error
	}
	return 3 // Domain name does not exists
}

// UploadRR to Cassandra Cluster from line
func (r *RedisKVS) UploadRR(line string) error {

	// Capture tokens
	tk := strings.Split(line, "\t")
	var dnsType string = tk[3]

	rclient := r.client
	switch dnsType {
	case "A":
		_, err := rclient.SAdd(tk[0]+":A", tk[1]+" "+tk[4]).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "NS":
		_, err := rclient.SAdd(tk[0]+":NS", tk[1]+" "+tk[4]).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "CNAME":
		_, err := rclient.SAdd(tk[0]+":CNAME", tk[1]+" "+tk[4]).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "SOA":
		_, err := rclient.Set(tk[0]+":SOA", tk[1]+" "+tk[4], 0).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "PTR":

		// Check that domain name is in-addr.arpa compliant
		// Just in case the record was added as an IP and answer
		var domain string = tk[0]
		if strings.Contains(domain, "in-addr.arpa") {
			domain, _ = dns.ReverseAddr(domain)
		}
		_, err := rclient.Set(domain+":PTR", tk[1]+" "+tk[4], 0).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "HINFO":
		_, err := rclient.SAdd(tk[0]+":HINFO", tk[1]+" "+tk[4]).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "MX":
		_, err := rclient.SAdd(tk[0]+":MX", tk[1]+" "+tk[4]).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	case "TXT":
		_, err := rclient.RPush(tk[0]+":TXT", tk[1]+" "+strings.ReplaceAll(tk[4], "\"", "")).Result()
		if err != nil {
			log.Printf("Error at redis uploading %s: %v", tk[0], err)
			return err
		}
	}
	return nil
}

// HandleFile reads a file containing RRs a uploads them replacing if set
func (r *RedisKVS) HandleFile(location string, replace bool) {
	log.Println("Not implemented")
	return
}

// Disconnect : Closes the Redis client
func (r *RedisKVS) Disconnect() {
	err := r.client.Close()
	if err != nil {
		log.Fatal(err)
	}
}

// ConnectDB : assign redis cluster client given the IPs and ports
func (r *RedisKVS) ConnectDB(ips []string) {
	// []string{":7000", ":7001", ":7002", ":7003", ":7004", ":7005"}
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: ips,
	})
	r.client = rdb
}

// Handle : function to call on the dns server when a package is received.
// Prepares the package and calls Redis to fill it up
func (r *RedisKVS) Handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)

	if *printf {
		logQuery(req)
	}

	if req.MsgHdr.Authoritative {
		rcode := r.MakeQuery(m)
		m.MsgHdr.Rcode = rcode
		w.WriteMsg(m)
	} else {
		m.MsgHdr.Rcode = 4 // Not implemented
		w.WriteMsg(m)
	}
}
