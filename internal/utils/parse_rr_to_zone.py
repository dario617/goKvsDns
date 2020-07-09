"""
Read Resource records from a list and create basic zone files

The script will create zone files for a domain. It will take a SOA
record from any of it's sub domains and use it for the entire zone.
If no SOA record is found a default it's used.

TODO: recover and apply individual TTL from each record. Now it uses a default
for each of them.

@author Dario Palma dpalma@dcc.uchile.cl
"""
import argparse
import coloredlogs
import logging

# TODO: implement TTL from RR
def createTree(root_dict, fqd, rr, value, ttl):
  # Split in tokens the string
  tokens = fqd.split(".")[:-1] #Ignore empty
  sub_domain = "n_v"
  if len(tokens) != 2:
    sub_domain = ".".join(tokens[0:-2])
  try:
    if not (tokens[-1] in root_dict):
      root_dict[tokens[-1]] = dict()
    if not (tokens[-2] in root_dict[tokens[-1]]):
      root_dict[tokens[-1]][tokens[-2]] = dict()
    if not (sub_domain in root_dict[tokens[-1]][tokens[-2]]):
      root_dict[tokens[-1]][tokens[-2]][sub_domain] = dict()
    if not (rr in root_dict[tokens[-1]][tokens[-2]][sub_domain]):
      if rr != "SOA" and rr != "TXT":
        root_dict[tokens[-1]][tokens[-2]][sub_domain][rr] = set()

    # Add value
    if rr != "SOA" and rr != "TXT":
      root_dict[tokens[-1]][tokens[-2]][sub_domain][rr].add(value)
      #root_dict[tokens[-1]][tokens[-2]][sub_domain][rr+"TTL"] = ttl
    else:
      root_dict[tokens[-1]][tokens[-2]][sub_domain][rr] = value
  except Exception as e:
    logger.error("Error %s at domain %s",e, fqd)


def exportDomainsToFile(root_dict, single_file, default_ttl="1d", soa="default"):
  """
  Write zones to one or multiple file zones and create a lists of available domains
  """
  rrs = ["A", "TXT", "SOA", "HINFO", "MX", "CNAME", "NS"]
  soa_v = "ns.example.com. username.example.com. ( 2000073131 1d 2h 4w 1h )"
  if soa != "default":
    soa_v = soa
  c_zones = 0
  c_soas = 0

  zone_list = []

  for tld in root_dict.keys():
    domain_dict = root_dict[tld]
    for domain in domain_dict.keys():
      sub_domains = domain_dict[domain]
      file_name = domain + "." + tld + ".zone"
      mode = "w"
      if single_file != False:
        file_name = single_file
        mode = "a"
      with open(file_name,mode) as file:
        # Write domain name
        file.write("$ORIGIN "+domain + "." + tld + ".\n")
        # Write default TTL
        file.write("$TTL "+default_ttl+"\n")
        soa_recovered = ""
        values = list()
        for subdomain in sub_domains:
          if subdomain not in rrs:
            records = sub_domains[subdomain]
            for record in records:
              current_sub_dom = subdomain + "."
              if subdomain == "n_v":
                current_sub_dom = ""
              if record == "TXT":
                values.append(current_sub_dom+domain + "." + tld + ".  IN  "+record+"  "+records[record]+"\n")
              elif record == "SOA":
                soa_recovered = records[record]
              else:
                record_values = records[record] 
                for r_value in record_values:
                   values.append(current_sub_dom+domain + "." + tld + ".  IN  "+record+"  "+r_value+"\n")
          else:
            # Abort
            print("wait what")
            print(subdomain, domain, tld)
            exit(0)
            values.append(domain + "." + tld + ".  IN  "+subdomain+"  "+sub_domains[subdomain]+"\n")
        # Save to file
        if soa_recovered == "":
          soa_recovered = soa_v
        else:
          c_soas = c_soas + 1
        file.write(domain + "." + tld + ".  IN  SOA  "+soa_recovered+"\n")
        for rr in values:
          file.write(rr)
        if single_file != False:
          file.write("\n")
      zone_list.append(domain+"."+tld)
      c_zones = c_zones + 1
  
  with open("parsed_zonelist", "w") as f:
    for line in zone_list:
      f.write(line+"\n")

  return c_zones, c_soas

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Recover Zones from a list of RR to multiple files")
  parser.add_argument("f", type=str, help="File to read RR from")
  parser.add_argument('-o', "--output_file", help="Optional single zone file name", default=False)
  args = parser.parse_args()

  FORMAT = '%(asctime)-15s %(message)s'
  coloredlogs.install()
  logging.basicConfig(format=FORMAT, level=logging.DEBUG)
  logger = logging.getLogger()

  # Create tree
  rr_tree = dict()
  c = 0
  logger.info("Reading records")
  with open(args.f) as f:
    for line in f:
      tokens = line[:-1].split("\t")
      createTree(rr_tree,tokens[0],tokens[3],tokens[4],tokens[1])
      if c%100000 == 0:
        logger.info("Read %s resource records",c)
      c = c + 1
  logger.info("Records: %s",c)
  logger.info("Saving as zone files...")
  zones, soa_used = exportDomainsToFile(rr_tree, args.output_file)
  logger.info("Created %d zones and recovered %d soa records", zones, soa_used)