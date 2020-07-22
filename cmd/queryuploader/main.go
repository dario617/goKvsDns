//
// Read DNS RR from a file to upload its contents to a db
// of the users choice
//
// Basic use pattern:
//
//   queryuploader --clusterIPs 192.168.0.2,192.168.0.3 --db cassandra --df ./file
//
// Or if the data is on different zonefiles you can read them by:
//
//   queryuploader --clusterIPs 192.168.0.2,192.168.0.3 --db cassandra --useZones --dd ./zones
//
// NB: add the necessary ports for each redis and etcd server.
// Consider this operation very taxing for a large dataset
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
	"sync"
	"syscall"
	"time"

	"github.com/dario617/goKvsDns/internal/server"
	"github.com/dario617/goKvsDns/internal/utils"
)

var (
	datasetFile   = flag.String("df", "./data/dataset/dns-rr.txt", "File to read RR from")
	useZones      = flag.Bool("useZones", false, "use Zones instead of a RR list file")
	datasetFolder = flag.String("dd", "./data/zones", "Directory containing zones")
	db            = flag.String("db", "cassandra", "db to connect: cassandra|redis|etcd")
	clusterIPs    = flag.String("clusterIPs", "192.168.0.240,192.168.0.241,192.168.0.242", "comma separated IP list")
	routines      = flag.Int("routines", 1, "number of subroutines")
	verbose       = flag.Bool("v", false, "Print to stdout progress and logs")
)

var values = map[string]int{
	"IN": 1,
}

func readFile(ch chan string, name string, wg *sync.WaitGroup) {
	defer os.Exit(0)

	file, err := os.Open(name)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	var count uint64 = 0
	for scanner.Scan() {
		ch <- scanner.Text()

		count++
		if count%1000 == 0 && *verbose {
			log.Println("Did ", count)
		}
	}

	wg.Done()
	// When upload is complete exit
	wg.Wait()
}

func readZones(ch chan string, name string, wg *sync.WaitGroup) {
	defer os.Exit(0)

	files, err := ioutil.ReadDir(name)
	if err != nil {
		log.Fatal(err)
	}

	var count uint64 = 0
	for _, file := range files {
		records, err := utils.ReadAndParseZoneFile(name+"/"+file.Name(), "")

		if err != nil {
			log.Printf("Error parsing %s: %v", name+"/"+file.Name(), err)
		}

		for _, rr := range records {
			ch <- rr.String()
			count++
			if count%1000 == 0 && *verbose {
				log.Println("Did ", count)
			}
		}
	}

	wg.Done()
	// When upload is complete exit
	close(ch)
	wg.Wait()
}

func uploadWorker(driver server.DBDriver, lines chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	log.Println("Started goroutine")
	for l := range lines {
		err := driver.UploadRR(l)
		if err != nil && *verbose {
			log.Printf("Error uploading %s: %v", l, err)
		}
	}
}

func main() {

	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	var wg sync.WaitGroup

	// Create channel and open file
	// The following routines will call for a halt when they are done
	// or die unexpectedly on a bad line
	lines := make(chan string)
	if *useZones {
		wg.Add(1)
		go readZones(lines, *datasetFolder, &wg)
	} else {
		wg.Add(1)
		go readFile(lines, *datasetFile, &wg)
	}

	// Connect to db
	var driver server.DBDriver
	switch *db {
	case "cassandra":
		var d *server.CassandraDB = new(server.CassandraDB)
		d.Print = *verbose
		driver = d
	case "redis":
		var d *server.RedisKVS = new(server.RedisKVS)
		d.Print = *verbose
		driver = d
	case "etcd":
		var d *server.EtcdDB = new(server.EtcdDB)
		d.Print = *verbose
		d.Timeout = 5 * time.Second
		driver = d
	}

	driver.ConnectDB(strings.Split(*clusterIPs, ","))
	log.Printf("DB %s connected for cluster %v\n", *db, *clusterIPs)
	defer driver.Disconnect()

	for i := 0; i < *routines; i++ {
		wg.Add(1)
		go uploadWorker(driver, lines, &wg)
	}

	// Manual process termination
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("Signal (%s) received, stopping\n", s)
}
