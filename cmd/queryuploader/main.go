//
// Read DNS RR from a file to upload its contents to a db
// of the users choice
//
// Basic use pattern:
//
//   queryuploader -clusterIPs 192.168.0.2,192.168.0.3 -db cassandra -datasetFile ./file
//
//
package queryuploader

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

// Make a query to the database and
// store the results on the Msg
func makeCassandraQuery(s *gocql.Session, line string) {

	// Capture tokens
	tk := strings.Split(line, " ")

	switch tk[3] {
	case "A":
		if err := s.Query(`INSERT INTO domain_a (domain_name, id, class, ttl, address) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "NS":
		if err := s.Query(`INSERT INTO domain_ns (domain_name, id, class, ttl, nsdname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "CNAME":
		if err := s.Query(`INSERT INTO domain_cname (domain_name, id, class, ttl, domain_cname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "SOA":
		if err := s.Query(`INSERT INTO domain_soa (domain_name, id, class, ttl, mname, rname, serial, refresh, retry, expire, minimum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4], tk[5], tk[6], tk[7], tk[8], tk[9], tk[10]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "PTR":
		if err := s.Query(`INSERT INTO domain_ptr (domain_name, id, class, ttl, ptrdname) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "HINFO":
		if err := s.Query(`INSERT INTO domain_hinfo (domain_name, id, class, ttl, cpu, os) VALUES (?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4], tk[5]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "MX":
		if err := s.Query(`INSERT INTO domain_hinfo (domain_name, id, class, ttl, preference, exchange) VALUES (?, ?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4], tk[5]).Exec(); err != nil {
			log.Fatal(err)
		}

	case "TXT":
		if err := s.Query(`INSERT INTO domain_hinfo (domain_name, id, class, ttl, data) VALUES (?, ?, ?, ?, ?)`,
			tk[0], gocql.TimeUUID(), tk[1], tk[2], tk[4], tk[5]).Exec(); err != nil {
			log.Fatal(err)
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
	session, _ := cluster.CreateSession()
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
		log.Fatal("Not yet implemented")
		return
	case "pebble":
		log.Fatal("Not yet implemented")
		return
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
