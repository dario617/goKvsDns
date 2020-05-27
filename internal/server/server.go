package server

import (
	"log"
	"strconv"
	"strings"

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
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the "+net+" server: %s\n", err.Error())
	}
	log.Printf("Started a server on port %d...\n", port)
}

func Start(db, rawIps string, soreuseport, port int, verbose bool) DBDriver {

	var ips []string = strings.Split(rawIps, ",")
	var driver DBDriver
	switch db {
	case "cassandra":
		var d *CassandraDB = new(CassandraDB)
		d.print = verbose
		driver = d
	case "redis":
		var d *RedisKVS = new(RedisKVS)
		d.print = verbose
		driver = new(RedisKVS)
	case "etcd":
		var d *EtcdDB = new(EtcdDB)
		d.print = verbose
		driver = new(EtcdDB)
	}

	driver.ConnectDB(ips)
	log.Printf("DB %s connected for cluster %v\n", db, ips)
	dns.HandleFunc(".", driver.Handle)

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
