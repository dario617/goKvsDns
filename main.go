// Copyright 2020 Dario Palma. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.
//
// Go DNS server is a nameserver that uses Distributed Key Value Stores
// to handle the DNS Resource Records.
// It admits queries of type A, AAAA, NS, TXT, PTR, CNAME, SOA and MX
// acting as an authorative DNS server.
//
// Basic use pattern:
//  go-kvs-dns-server --clusterIPs "192.168.0.240,192.168.0.241,192.168.0.242" \
//    --print --db cassandra --port 8053
//
// then:
//	dig @localhost -p 8053 this.is.my.domain.andhael.cl A
//
//	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2157
//	;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
//	;; QUESTION SECTION:
//	;this.is.my.domain.andhael.cl.			IN	A
//
//	;; ANSWER SECTION:
//	this.is.my.domain.andhael.cl.		0	IN	A	127.0.0.1
//
//	;; ADDITIONAL SECTION:
//	this.is.my.domain.andhael.cl.		0	IN	TXT	"Port: 56195 (udp)"
//
// Inspired on Reflect Server by Miek Gieben <miek@miek.nl>.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
)

var (
	cpuprofile  = flag.String("cpuprofile", "", "write cpu profile to file")
	printf      = flag.Bool("print", false, "print replies")
	port        = flag.Int("port", 8053, "port to use")
	soreuseport = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu         = flag.Int("cpu", 0, "number of cpu to use")
	db          = flag.String("db", "cassandra", "db to connect: cassandra|redis|pebble")
	clusterIPs  = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
	conf        = flag.String("conf", "./conf/conf.yml", "configuration file")
)

func main() {
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

	start()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
