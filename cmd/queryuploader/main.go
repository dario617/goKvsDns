//
// Read DNS RR from a file to upload its contents to a db
// of the users choice
//
// Basic use pattern:
//
//   queryuploader --clusterIPs 192.168.0.2,192.168.0.3 --db cassandra --datasetFile ./file
//
// Or if the data is on different zonefiles you can read them by:
//
//   queryuploader --clusterIPs 192.168.0.2,192.168.0.3 --db cassandra --useZones true --datasetFolder ./zones
//
package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dario617/goKvsDns/internal/server"
	"github.com/dario617/goKvsDns/internal/utils"
)

var (
	datasetFile   = flag.String("datasetFile", "./data/dataset/dns-rr.txt", "File to read RR from")
	useZones      = flag.Bool("useZones", false, "use Zones instead of a RR list file")
	datasetFolder = flag.String("datasetFolder", "./data/zones", "Folder containing zones")
	db            = flag.String("db", "cassandra", "db to connect: cassandra|redis|pebble")
	clusterIPs    = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
)

var values = map[string]int{
	"IN": 1,
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

func readZones(ch chan string, name string) {
	files, err := ioutil.ReadDir(name)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		records, err := utils.ReadAndParseZoneFile(file.Name(), "")

		if err != nil {
			log.Printf("Error parsing %s: %v", file.Name(), err)
		}

		for _, rr := range records {
			ch <- rr.String()
		}
	}
}

func main() {

	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	// Create channel and open file
	lines := make(chan string)
	if *useZones {
		go readZones(lines, *datasetFolder)
	} else {
		go readFile(lines, *datasetFile)
	}

	// Connect to db
	var driver server.DBDriver
	switch *db {
	case "cassandra":
		driver = new(server.CassandraDB)
	case "redis":
		driver = new(server.RedisKVS)
	case "etcd":
		driver = new(server.EtcdDB)
	}

	driver.ConnectDB(strings.Split(*clusterIPs, ","))
	log.Printf("DB %s connected for cluster %v\n", *db, *clusterIPs)
	defer driver.Disconnect()

	go func() {
		var count uint64 = 0
		for l := range lines {
			err := driver.UploadRR(l)
			if err != nil {
				log.Printf("Error uploading %s: %v", l, err)
			}
			count++
			if count%1000 == 0 {
				log.Println("Did ", count)
			}
		}
	}()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
