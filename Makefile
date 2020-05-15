# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAME=kvs-dns

# Database config
# Select from cassandra,redis,etcd
DB=cassandra
RUN_DB=run_$(DB)
STOP_DB=stop_$(DB)
ANSIBLE_DIR=./scripts/ansible

all: $(RUN_DB) build

build:
		$(GOBUILD) -o $(BINARY_NAME) -v

test:
		$(GOTEST) -v ./...

clean: $(STOP_DB)
		$(GOCLEAN)
		@rm -f $(BINARY_NAME)

run: $(RUN_DB)
		$(GOBUILD) -o $(BINARY_NAME) -v ./...
		./$(BINARY_NAME)

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