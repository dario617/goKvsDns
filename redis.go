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

func makeQueryRedis(rclient *redis.ClusterClient, m *dns.Msg) {
	var dnsq dns.Question = m.Question[0]

	switch dnsq.Qtype {
	case dns.TypeA:

		rrVal, err := rclient.LRange(dnsq.Name+":A", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
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

		rrVal, err := rclient.LRange(dnsq.Name+":NS", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
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

		rrVal, err := rclient.LRange(dnsq.Name+":CNAME", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
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

		rrVal, err := rclient.LRange(dnsq.Name+":NS", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
		} else {
			for i := range rrVal {
				// ttl mname rname serial refresh retry expire minimum
				values := strings.Split(rrVal[i], " ")
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
		}

	case dns.TypePTR:

		rrVal, err := rclient.LRange(dnsq.Name+":PTR", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
		} else {
			for i := range rrVal {
				// TTL PTRDNAME
				values := strings.Split(rrVal[i], " ")
				ttl, _ := strconv.Atoi(values[0])
				rr := &dns.PTR{
					Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)},
					Ptr: values[1],
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	case dns.TypeHINFO:

		rrVal, err := rclient.LRange(dnsq.Name+":HINFO", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
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

		rrVal, err := rclient.LRange(dnsq.Name+":MX", 0, -1).Result()
		if err == redis.Nil {
			fmt.Println("no value found")
		} else if err != nil {
			panic(err)
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
			panic(err)
		} else {
			ttl, _ := strconv.Atoi(rrVal[0])
			rr := &dns.TXT{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Txt: rrVal[1:],
			}
			m.Answer = append(m.Answer, rr)
		}
	}
}

func disconnectRedis(rclient *redis.ClusterClient) {
	err := rclient.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func connectToRedis() *redis.ClusterClient {
	// []string{":7000", ":7001", ":7002", ":7003", ":7004", ":7005"}
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: strings.Split(*clusterIPs, ","),
	})

	return rdb
}

func handleRedis(w dns.ResponseWriter, r *dns.Msg, rclient *redis.ClusterClient) {
	m := new(dns.Msg)
	m.SetReply(r)

	if *printf {
		fmt.Printf("%v\n", m.String())
	}

	makeQueryRedis(rclient, m)
	w.WriteMsg(m)
}
