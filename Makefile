# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAME=KvsDns

# Database config
# Select from cassandra,redis,etcd
DB=cassandra
CLUSTER_IPS="192.168.0.240,192.168.0.241,192.168.0.242"
CPU_NUMBER=4
RUN_DB=run_$(DB)
STOP_DB=stop_$(DB)
ANSIBLE_DIR=./scripts/ansible

build:
		@$(GOBUILD) -o $(BINARY_NAME) -v

test:
		@$(GOTEST) -v ./...

clean: $(STOP_DB)
		$(GOCLEAN)
		@rm -f $(BINARY_NAME)

run: $(RUN_DB)
		$(GOBUILD) -o $(BINARY_NAME) -v
		./$(BINARY_NAME) --clusterIPs $(CLUSTER_IPS) --print --soreuseport $(CPU_NUMBER) --cpu $(CPU_NUMBER)

run_standalone:
		$(GOBUILD) -o $(BINARY_NAME) -v
		./$(BINARY_NAME) --clusterIPs $(CLUSTER_IPS) --print --soreuseport $(CPU_NUMBER) --cpu $(CPU_NUMBER)

build_cmd: build_requester build_uploader

build_requester:
		@cd cmd/dnsrequester && $(GOBUILD) -v

build_uploader:
		@cd cmd/queryuploader && $(GOBUILD) -v
		
# Key value store targets using ansible
run_cassandra:
		@cd $(ANSIBLE_DIR) && ansible-playbook --ask-become-pass playbooks/cassandra_up.yml
stop_cassandra:
		@cd $(ANSIBLE_DIR) && ansible-playbook --ask-become-pass playbooks/cassandra_down.yml

run_redis:
		@cd $(ANSIBLE_DIR) && ansible-playbook --ask-become-pass playbooks/redis_up.yml
stop_redis:
		@cd $(ANSIBLE_DIR) && ansible-playbook --ask-become-pass playbooks/redis_down.yml

run_etcd:
		@cd $(ANSIBLE_DIR) && ansible-playbook --ask-become-pass playbooks/etcd_up.yml
stop_etcd:
		@cd $(ANSIBLE_DIR) && ansible-playbook --ask-become-pass playbooks/etcd_down.yml