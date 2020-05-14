//
// Read DNS RR from a file to upload its contents to a db
// of the users choice
//
// Basic use pattern:
//
//   queryuploader -clusterIPs 192.168.0.2,192.168.0.3 -db cassandra -datasetFile ./file
//
//
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gocql/gocql"
)

var (
	datasetFile = flag.String("datasetFile", "./data/dataset/dns-rr.txt", "File to read RR from")
	db          = flag.String("db", "cassandra", "db to connect: cassandra|redis|pebble")
	clusterIPs  = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
	conf        = flag.String("conf", "./conf/conf.yml", "configuration file")
)

var values = map[string]int{
	"IN": 1,
}

// Make a query to the database and
// store the results on the Msg
func makeCassandraQuery(s *gocql.Session, line string) {

	// Capture tokens
	tk := strings.Split(line, "\t")
	var dnsType string = tk[3]

	switch dnsType {
	case "A":
		if err := s.Query(`INSERT INTO domain_a (domain_name, id, class, ttl, address) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("A", tk, err)
				// Retry
			}
		}
	case "NS":
		if err := s.Query(`INSERT INTO domain_ns (domain_name, id, class, ttl, nsdname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				log.Fatal("NS", tk, err)
			} else {
				// Retry
				makeCassandraQuery(s, line)
			}
		}
	case "CNAME":
		if err := s.Query(`INSERT INTO domain_cname (domain_name, id, class, ttl, domain_cname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("CNAME", tk, err)
				// Retry
			}
		}
	case "SOA":
		soa_data := strings.Split(tk[4], " ")
		if err := s.Query(`INSERT INTO domain_soa (domain_name, id, class, ttl, mname, rname, serial, refresh, retry, expire, minimum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], soa_data[0], soa_data[1], soa_data[2], soa_data[3], soa_data[4], soa_data[5], soa_data[6]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("SOA", tk, err)
				// Retry
			}
		}
	case "PTR":
		if err := s.Query(`INSERT INTO domain_ptr (domain_name, id, class, ttl, ptrdname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], tk[4]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("PTR", tk, err)
				// Retry
			}
		}
	case "HINFO":
		hinfo_data := strings.Split(tk[4], " ")
		if err := s.Query(`INSERT INTO domain_hinfo (domain_name, id, class, ttl, cpu, os) VALUES (?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], hinfo_data[0], hinfo_data[1]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("HINFO", tk, err)
				// Retry
			}
		}
	case "MX":
		mx_data := strings.Split(tk[4], " ")
		if err := s.Query(`INSERT INTO domain_mx (domain_name, id, class, ttl, preference, exchange) VALUES (?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], mx_data[0], mx_data[1]).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("MX", tk, err)
				// Retry
			}
		}
	case "TXT":
		if err := s.Query(`INSERT INTO domain_txt (domain_name, id, class, ttl, txt) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), values[tk[2]], tk[1], strings.ReplaceAll(tk[4], "\"", "")).Exec(); err != nil {
			if err == gocql.ErrTimeoutNoResponse || err == gocql.ErrConnectionClosed {
				makeCassandraQuery(s, line)
			} else {
				log.Fatal("TXT", tk, err)
				// Retry
			}
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

func readFile(ch chan string, name string) {
	file, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		ch <- scanner.Text()
	}
}

func main() {

	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	// Create channel and open file
	lines := make(chan string)
	go readFile(lines, *datasetFile)

	// Connect to db
	switch *db {
	case "cassandra":
		session := connectToCassandra()
		defer disconnectCassandra(session)

		for l := range lines {
			makeCassandraQuery(session, l)
		}
	case "redis":
		log.Fatal("Redis: Not yet implemented")
		return
	case "pebble":
		log.Fatal("Pebble: Not yet implemented")
		return
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
