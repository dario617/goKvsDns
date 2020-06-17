package server

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/etcdserver/api/v3rpc/rpctypes"
)

// EtcdDB : Implements DBDriver and holds the etcd client
type EtcdDB struct {
	client  *clientv3.Client
	Timeout time.Duration
	Print   bool
}

// Disconnect : Closes the Ectd client
func (edb *EtcdDB) Disconnect() {
	edb.client.Close()
}

// ConnectDB : assign etcd cluster client given the IPs and ports
func (edb *EtcdDB) ConnectDB(ips []string) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   ips,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Error while connecting to Etcd cluster %v", err)
	}
	edb.client = cli
}

// recoverKey  from Etcd cluster using a timeout
func (edb *EtcdDB) recoverKey(key string) (string, error) {
	cli := edb.client
	requestTimeout := edb.Timeout
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	resp, err := cli.Get(ctx, key)
	defer cancel()

	if err != nil {
		switch err {
		case context.Canceled:
			log.Printf("ctx is canceled by another routine: %v\n", err)
		case context.DeadlineExceeded:
			log.Printf("ctx is attached with a deadline is exceeded: %v\n", err)
		case rpctypes.ErrEmptyKey:
			log.Printf("client-side error: %v\n", err)
		default:
			log.Printf("bad cluster endpoints, which are not etcd servers: %v\n", err)
		}
		return "", err
	}

	if len(resp.Kvs) == 0 {
		return "", nil
	}
	return string(resp.Kvs[0].Value), nil
}

// putValueOnSet checks if value is present on set (a line). If not then it adds it
// A value is described the value in a pair TTL Value
func (edb *EtcdDB) putValueOnSet(key, value *string) error {
	// Recover full value
	resp, err := edb.recoverKey(*key)
	if err != nil {
		return err
	}

	var repeated bool = false
	records := strings.Split(resp, ",")
	if resp != "" {
		// Value ignoring TTL
		val := strings.Split(*value, " ")[1]
		// Check that we are not repeating our selves
		for i := range records {
			recordValue := strings.Split(records[i], " ")[1]
			if recordValue == val {
				repeated = true
				// If repeated replace the value at position i
				records[i] = *value
				break
			}
		}
	}

	var newValue string = resp
	// Create new answer set
	if !repeated {
		if newValue == "" {
			newValue = *value
		} else {
			newValue = resp + "," + *value
		}
	} else {
		newValue = strings.Join(records, ",")
	}
	cli := edb.client
	requestTimeout := edb.Timeout
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	_, err = cli.Put(ctx, *key, newValue)
	cancel()
	if err != nil {
		return err
	}
	return nil
}

// putTXTOnList by reading the value: [TTL, Value] and appending to the
// string RR list if the TTL is the same
func (edb *EtcdDB) putTXTOnList(key *string, value []string) error {
	// Recover full value
	resp, err := edb.recoverKey(*key)
	if err != nil {
		return err
	}

	var newValue string = resp
	records := strings.Split(resp, ",")
	// Check that TTL is the same
	if records[0] == value[0] {
		// Check that we are not repeating our selves
		var repeated bool = false
		for i := range records {
			if i == 0 {
				continue
			}
			if records[i] == value[1] {
				repeated = true
				// If repeated replace the value at position i
				records[i] = value[1]
				break
			}
		}
		if !repeated {
			newValue = resp + "," + value[1]
		} else {
			newValue = strings.Join(records, ",")
		}
		// Take different TTLs as a complete update of the RR
	} else {
		newValue = strings.Join(value, ",")
	}
	cli := edb.client
	requestTimeout := edb.Timeout
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	_, err = cli.Put(ctx, *key, newValue)
	cancel()
	if err != nil {
		return err
	}
	return nil
}

// MakeQuery : using a valid Etcd Client
// makes a get query
//
// Records will be in format
// DomainName:Type "TTL VALUES,TTL VALUES..."
func (edb *EtcdDB) MakeQuery(m *dns.Msg) int {

	var dnsq dns.Question = m.Question[0]

	switch dnsq.Qtype {
	case dns.TypeA:
		resp, err := edb.recoverKey(dnsq.Name + ":A")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		for i := range records {
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
				A:   net.ParseIP(values[1]).To4(),
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeNS:
		resp, err := edb.recoverKey(dnsq.Name + ":NS")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL NSDNAME
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.NS{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Ns:  values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeCNAME:
		resp, err := edb.recoverKey(dnsq.Name + ":CNAME")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL DOMAIN_NAME
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.CNAME{
				Hdr:    dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Target: values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeSOA:
		resp, err := edb.recoverKey(dnsq.Name + ":SOA")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		values := strings.Split(resp, " ")
		// ttl mname rname serial refresh retry expire minimum
		ttl, _ := strconv.Atoi(values[0])
		serial, _ := strconv.Atoi(values[3])
		refresh, _ := strconv.Atoi(values[4])
		retry, _ := strconv.Atoi(values[5])
		expire, _ := strconv.Atoi(values[6])
		mintll, _ := strconv.Atoi(values[7])
		rr := &dns.SOA{
			Hdr:     dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Ns:      values[1],
			Mbox:    values[2],
			Serial:  uint32(serial),
			Refresh: uint32(refresh),
			Retry:   uint32(retry),
			Expire:  uint32(expire),
			Minttl:  uint32(mintll)}
		m.Answer = append(m.Answer, rr)
	case dns.TypePTR:
		resp, err := edb.recoverKey(dnsq.Name + ":PTR")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL PTRDNAME
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.PTR{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Ptr: values[1],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeHINFO:
		resp, err := edb.recoverKey(dnsq.Name + ":HINFO")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL CPU OS
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			rr := &dns.HINFO{
				Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Cpu: values[1],
				Os:  values[2],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeMX:
		resp, err := edb.recoverKey(dnsq.Name + ":MX")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		for i := range records {
			// TTL preference exchange
			values := strings.Split(records[i], " ")
			ttl, _ := strconv.Atoi(values[0])
			preference, _ := strconv.Atoi(values[1])
			rr := &dns.MX{
				Hdr:        dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: uint32(ttl)},
				Preference: uint16(preference),
				Mx:         values[2],
			}
			m.Answer = append(m.Answer, rr)
		}
	case dns.TypeTXT:
		resp, err := edb.recoverKey(dnsq.Name + ":TXT")
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return 2 // Server Problem
		}
		// TTL val1 val2 val3 ...
		if resp == "" {
			// No value found
			return 0 // No error
		}
		records := strings.Split(resp, ",")
		ttl, _ := strconv.Atoi(records[0])
		rr := &dns.TXT{
			Hdr: dns.RR_Header{Name: dnsq.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Txt: records[1:],
		}
		m.Answer = append(m.Answer, rr)
	}

	if len(m.Answer) >= 1 {
		return 0 // No error
	}
	return 3 // Domain name does not exists
}

// UploadRR to Etcd Cluster from line appending it to the end of the value
func (edb *EtcdDB) UploadRR(line string) error {

	tk := strings.Split(line, "\t")
	var dnsType string = tk[3]

	switch dnsType {
	case "A":
		var key string = tk[0] + ":A"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.putValueOnSet(&key, &newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "NS":
		var key string = tk[0] + ":NS"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.putValueOnSet(&key, &newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "CNAME":
		var key string = tk[0] + ":CNAME"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.putValueOnSet(&key, &newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "SOA":
		var key string = tk[0] + ":SOA"
		newValue := tk[1] + " " + tk[4]
		cli := edb.client
		requestTimeout := edb.Timeout
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err := cli.Put(ctx, key, newValue)
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "PRT":
		// Check that domain name is in-addr.arpa compliant
		// Just in case the record was added as an IP and answer
		var domain string = tk[0]
		if strings.Contains(domain, "in-addr.arpa") {
			domain, _ = dns.ReverseAddr(domain)
		}
		var key string = domain + ":PTR"
		newValue := tk[1] + " " + tk[4]
		cli := edb.client
		requestTimeout := edb.Timeout
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		_, err := cli.Put(ctx, key, newValue)
		cancel()
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "HINFO":
		var key string = tk[0] + ":HINFO"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.putValueOnSet(&key, &newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "MX":
		var key string = tk[0] + ":HINFO"
		var newRR string = tk[1] + " " + tk[4]

		err := edb.putValueOnSet(&key, &newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	case "TXT":
		var key string = tk[0] + ":TXT"
		var newRR []string = []string{tk[1], strings.ReplaceAll(tk[4], "\"", "")}

		err := edb.putTXTOnList(&key, newRR)
		if err != nil {
			log.Printf("Error on Etcd %v", err)
			return err
		}
	}
	return nil
}

// HandleFile reads a file containing RRs a uploads them replacing if set
func (edb *EtcdDB) HandleFile(location string, replace bool) {
	log.Println("Not implemented")
	return
}

// Handle : function to call on the dns server when a package is received.
// Prepares the package and calls Etcd to fill it up
func (edb *EtcdDB) Handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if edb.Print {
		logQuery(r)
	}

	if r.MsgHdr.Authoritative {
		m.MsgHdr.Rcode = 4 // Not implemented
		w.WriteMsg(m)
	} else {
		rcode := edb.MakeQuery(m)
		m.MsgHdr.Rcode = rcode
		w.WriteMsg(m)
	}
}
