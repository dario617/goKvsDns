CREATE KEYSPACE IF NOT EXISTS dns
    WITH replication = {'class': 'SimpleStrategy', 'replication_factor' : 3};

USE dns;

CREATE TABLE  IF NOT EXISTS domain_a (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    address text,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_ns (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    nsdname text,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_cname (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    domain_cname text,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_soa (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    mname text,
    rname text,
    serial int,
    refresh int,
    retry int,
    expire int,
    minimum int,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_ptr (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    ptrdname text,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_hinfo (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    cpu text,
    os text,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_mx (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    preference int,
    exchange text,
    PRIMARY KEY (domain_name, id)
);

CREATE TABLE  IF NOT EXISTS domain_txt (
    domain_name text,
    id uuid,
    class smallint,
    ttl int,
    txt text,
    PRIMARY KEY (domain_name, id)
);