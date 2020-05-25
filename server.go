package main

import (
	"log"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// DBDriver : Database driver interface
type DBDriver interface {
	MakeQuery(m *dns.Msg) int
	ConnectDB(ips []string)
	Disconnect()
	Handle(w dns.ResponseWriter, r *dns.Msg)
}

func logQuery(m *dns.Msg) {
	log.Printf("%v\n", m.String())
}

func serve(net string, soreuseport bool) {
	server := &dns.Server{Addr: "[::]:" + strconv.Itoa(*port), Net: net, TsigSecret: nil, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
	log.Printf("Started a server on port %d...\n", *port)
}

func start(db, rawIps string) DBDriver {

	var ips []string = strings.Split(rawIps, ",")
	var driver DBDriver
	switch db {
	case "cassandra":
		driver = new(CassandraDB)
	case "redis":
		driver = new(RedisKVS)
	case "etcd":
		driver = new(EtcdDB)
	}

	driver.ConnectDB(ips)
	log.Printf("DB %s connected for cluster %v\n", db, ips)
	dns.HandleFunc(".", driver.Handle)

	if *soreuseport > 0 {
		for i := 0; i < *soreuseport; i++ {
			go serve("tcp", true)
			go serve("udp", true)
		}
	} else {
		go serve("tcp", false)
		go serve("udp", false)
	}

	return driver
}
