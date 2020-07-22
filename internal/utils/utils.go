package utils

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// ReadAndParseZoneFile by providing the filename and a zoneName if available.
// If no zoneName is known use ""
// Based on github.com/niclabs/dns-tools/tools/context.go
func ReadAndParseZoneFile(fileName, zoneName string) ([]dns.RR, error) {
	rrs := make([]dns.RR, 0)
	currentZone := zoneName

	// Open file
	file, err := os.Open(fileName)
	if err != nil {
		return rrs, err
	}
	defer file.Close()

	zone := dns.NewZoneParser(file, currentZone, "")
	if err := zone.Err(); err != nil {
		return rrs, err
	}

	var soaRR dns.RR
	for rr, ok := zone.Next(); ok; rr, ok = zone.Next() {
		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			// parse only one SOA
			if soaRR != nil {
				continue
			}
			soaRR = rr.(*dns.SOA)
			// Getting zone name if it is not defined as argument
			if currentZone == "" {
				currentZone = rr.Header().Name
			}
			fallthrough
		default:
			rrs = append(rrs, rr)
		}
	}

	if soaRR == nil {
		return rrs, fmt.Errorf("SOA RR not found")
	}
	log.Printf("Zone parsed is %s\n", currentZone)

	// We check that all the rrs are from the defined zone
	zoneRRs := make([]dns.RR, 0)
	for _, rr := range rrs {
		if strings.HasSuffix(rr.Header().Name, currentZone) {
			zoneRRs = append(zoneRRs, rr)
		}
	}

	return zoneRRs, nil
}
