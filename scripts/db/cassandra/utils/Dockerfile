FROM cassandra:3.11.6
#COPY ./cassandra.yml /etc/cassandra/cassandra.yaml
COPY ./commands.cql /home/commands.cql
COPY ./init.sh /init.sh
ENTRYPOINT [ "bash","/init.sh" ]