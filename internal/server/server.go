package server

import (
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DBDriver : Database driver interface
type DBDriver interface {
	MakeQuery(m *dns.Msg) int
	UploadRR(line string) error
	HandleFile(location string, replace bool)
	ConnectDB(ips []string)
	Disconnect()
	Handle(w dns.ResponseWriter, r *dns.Msg)
}

// Unified query logging
func logQuery(m *dns.Msg) {
	log.Printf("%v\n", m.String())
}

func serve(net string, soreuseport bool, port int) {
	server := &dns.Server{Addr: "[::]:" + strconv.Itoa(port), Net: net, TsigSecret: nil, ReusePort: soreuseport}
	log.Printf("Starting a server on port %d...\n", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
}

// Start server
func Start(db, rawIps string, soreuseport, port int, verbose bool) DBDriver {

	var ips []string = strings.Split(rawIps, ",")
	var driver DBDriver
	switch db {
	case "cassandra":
		var d *CassandraDB = new(CassandraDB)
		d.Print = verbose
		driver = d
	case "redis":
		var d *RedisKVS = new(RedisKVS)
		d.Print = verbose
		driver = new(RedisKVS)
	case "etcd":
		var d *EtcdDB = new(EtcdDB)
		d.Print = verbose
		d.Timeout = 5 * time.Second
		driver = new(EtcdDB)
	}

	driver.ConnectDB(ips)
	log.Printf("DB %s connected for cluster %v\n", db, ips)
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		driver.Handle(w, r)
	})

	if soreuseport > 0 {
		for i := 0; i < soreuseport; i++ {
			go serve("tcp", true, port)
			go serve("udp", true, port)
		}
	} else {
		go serve("tcp", false, port)
		go serve("udp", false, port)
	}

	return driver
}
