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
	"syscall"

	gkvs "github.com/dario617/goKvsDns"
)

var (
	datasetFile = flag.String("datasetFile", "./data/dataset/dns-rr.txt", "File to read RR from")
	db          = flag.String("db", "cassandra", "db to connect: cassandra|redis|pebble")
	clusterIPs  = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
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

func main() {

	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	// Create channel and open file
	lines := make(chan string)
	go readFile(lines, *datasetFile)

	// Connect to db
	var driver gksv.DBDriver
	switch *db {
	case "cassandra":
		driver = new(gksv.CassandraDB)
	case "redis":
		driver = new(gksv.RedisKVS)
	case "etcd":
		driver = new(gksv.EtcdDB)
	}

	driver.ConnectDB(*clusterIPs)
	log.Printf("DB %s connected for cluster %v\n", *db, *clusterIPs)
	defer driver.Disconnect()

	go func (){
		var count uint64 = 0
		for l := range lines {
			err := driver.UploadRR(l)
			if err != nil{
				log.Printf("Error uploading %s: %v",l,err)
			}
			count++
			if count%1000 == 0 {
				fmt.Println("Did ", count)
			}
		}
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	fmt.Printf("Signal (%s) received, stopping\n", s)
}
