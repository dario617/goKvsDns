package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"go.etcd.io/etcd/clientv3"
)

// EtcdDB : Implements DBDriver and holds the etcd client
type EtcdDB struct {
	client  *clientv3.Client
	timeout time.Duration
}

// Disconnect : Closes the Ectd client
func (edb EtcdDB) Disconnect() {
	edb.client.Close()
}

// ConnectDB : assign etcd cluster client given the IPs and ports
func (edb EtcdDB) ConnectDB(ips []string) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   ips,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Error while connecting to Etcd cluster %v", err)
	}
	edb.client = cli
}

// MakeQuery : using a valid Etcd Client
// makes a get query
func (edb EtcdDB) MakeQuery(m *dns.Msg) {

	cli := edb.client
	requestTimeout := edb.timeout

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	resp, err := cli.Get(ctx, "foo")
	cancel()
	if err != nil {
		log.Fatal(err)
	}
	for _, ev := range resp.Kvs {
		fmt.Printf("%s : %s\n", ev.Key, ev.Value)
	}
	// Output: foo : bar
}

// Handle : function to call on the dns server when a package is received.
// Prepares the package and calls Etcd to fill it up
func (edb EtcdDB) Handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	edb.MakeQuery(m)
	w.WriteMsg(m)
}
