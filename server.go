package main

import (
	"log"
	"strconv"

	"github.com/miekg/dns"
)

func serve(net string, soreuseport bool) {
	server := &dns.Server{Addr: "[::]:" + strconv.Itoa(*port), Net: net, TsigSecret: nil, ReusePort: soreuseport}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

func start() {

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
	case "etcd":
		client := connectToEtcd()
		dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			handleEtcd(w, r, client)
		})
		defer disconnectEtcd(client)
	}

	if *soreuseport > 0 {
		for i := 0; i < *soreuseport; i++ {
			go serve("tcp", true)
			go serve("udp", true)
		}
	} else {
		go serve("tcp", false)
		go serve("udp", false)
	}

}
