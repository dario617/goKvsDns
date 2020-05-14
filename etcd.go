package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.etcd.io/etcd/clientv3"
)

func disconnectEtcd(cli *clientv3.Client) {
	cli.Close()
}

func makeQueryEtcd(cli *clientv3.Client, m *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 32)
	_, err := cli.Put(ctx, "sample_key", "sample_value")
	cancel()
	if err != nil {
		switch err {
		case context.Canceled:
			log.Fatalf("ctx is canceled by another routine: %v", err)
		case context.DeadlineExceeded:
			log.Fatalf("ctx is attached with a deadline is exceeded: %v", err)
		default:
			log.Fatalf("bad cluster endpoints, which are not etcd servers: %v", err)
		}
	}
}

func handleEtcd(w dns.ResponseWriter, r *dns.Msg, cli *clientv3.Client) {
	m := new(dns.Msg)
	m.SetReply(r)

	if *printf {
		fmt.Printf("%v\n", m.String())
	}

	makeQueryEtcd(cli, m)
	w.WriteMsg(m)
}

func connectToEtcd() *clientv3.Client {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   strings.Split(*clusterIPs, ","),
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Error while connecting to Etcd cluster %v", err)
	}
	return cli
}
