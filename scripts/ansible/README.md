# Ansible Setup

Extended ansible setup instructions

## Relevant variables

To connect you will need to modify the necessary variables on playbooks/group_vars/all
* host_1
* host_2
* host_3
* remote_user
and on inventory/hosts
* The server IPs
* Your SSH connection user which is normally the same as remote_user; the variable is ansible_user

## Reserved Users
| id    |    usage            |
|-------|:-------------------:|
| 1502  |  etcd               |
