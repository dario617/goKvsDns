# Go-KVS-DNS-Server

This is a DNS Server that uses one of three Key Value Databases (Cassandra is a Column Database but we use it as if) as a DNS Resource Record Backend to answer queries.

This application uses Redis, Cassandra or Etcd to store the RRs in a distributed fashion. This allows us to have atomic updates for each record, easy RR distribution accross a datacenter or multiple datacenters and reliability. 


No DNSSec is to be implemented.

## System requirements

Since the application is meant to be backend distributed with a single entrypoint you need at least 3 machines.

On the main machine:
* Go 1.14
* Ansible via python or package manager
* An SSH Key

On each machine:
* SSH-Server
* The following ports, which you can configure on the ansible inventory/group_vars
  * Redis: 7001,7002,7003,7004,7005,7006 and 17001,17002,17003,17004,17005,17006 since Redis uses "server port + 10" for intercluster gossip.
  * Cassandra: 7000, 9042, 9160
  * Etcd: **SOME PORT**

Ansible will compile each database on the system checking for the system requirements.

## Setup

First to set up the databases you need to have remote access to the remote machines and sudo access. 
The connection assumes the following:
* You have added your public key to the remote servers.
* The same user is present on every system.
* You have root privileges for each user.

Run the following scripts
```shell
$ Make setup
$ go build
```
then start the server with your
```shell
$ Make start "db"
$ ./go-dns-server --db dbname
```