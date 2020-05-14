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
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-redis/redis"
	"github.com/gocql/gocql"
	"github.com/miekg/dns"
	"go.etcd.io/etcd/clientv3"
)

var (
	cpuprofile  = flag.String("cpuprofile", "", "write cpu profile to file")
	printf      = flag.Bool("print", false, "print replies")
	compress    = flag.Bool("compress", false, "compress replies")
	port        = flag.Int("port", 8053, "port to use")
	soreuseport = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu         = flag.Int("cpu", 0, "number of cpu to use")
	db          = flag.String("db", "cassandra", "db to connect: cassandra|redis|pebble")
	clusterIPs  = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
	conf        = flag.String("conf", "./conf/conf.yml", "configuration file")
)

// Make a query to the database and
// store the results on the Msg
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

	makeQueryCassandra(s, m)

	w.WriteMsg(m)
}

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

func importTest() {
	cli, err1 := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379", "localhost:22379", "localhost:32379"},
		DialTimeout: 5 * time.Second,
	})
	if err1 != nil {
		// handle error!
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 32)
	_, err := cli.Put(ctx, "sample_key", "sample_value")
	cancel()
	if err != nil {
		switch err {
		case context.Canceled:
			log.Fatalf("ctx is canceled by another routine: %v", err)
		case context.DeadlineExceeded:
			log.Fatalf("ctx is attached with a deadline is exceeded: %v", err)
		default:
			log.Fatalf("bad cluster endpoints, which are not etcd servers: %v", err)
		}
	}
}

func handleRedis(w dns.ResponseWriter, r *dns.Msg, rclient *redis.ClusterClient) {
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

	makeQueryRedis(rclient, m)

	w.WriteMsg(m)
}

func serve(net, name, secret string, soreuseport bool) {
	server := &dns.Server{Addr: "[::]:" + strconv.Itoa(*port), Net: net, TsigSecret: nil, ReusePort: soreuseport}
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
		client := connectToRedis()
		dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			handleRedis(w, r, client)
		})
		defer disconnectRedis(client)
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
