import argparse
import os
import dns.resolver
import sys
import nmap

from checkdmarc import *
import socket

points = {}

def process(domain):
    
    # 6 Open resolver 
    resolver = dns.resolver.Resolver()
    ip = socket.gethostbyname(domain)
    # If we get an answer, it's open
    #try:
    #    
    #    resolver.nameservers = [ip]
    #    resolver.query(domain, 'A')
    #    print('%s,open' % (domain))
    #    points['resolver'] = True
    ## NoAnswer: Contacted a server but didn't get a valid response
    ## NoNameservers: Couldn't get a valid answer from any of the nameservers
    ## These probably mean it's closed
    #except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
    #    print('%s,closed' % (domain))
    ## No response
    #except dns.resolver.Timeout:
    #    print('%s,closed' % (domain))
    #    points['resolver']=  True
    #    pass

    # Response time on every server

    # IPV6 support
    try: 
        dns.resolver.query(domain, "AAAA")
        points['IPV6 support'] = True
    except dns.resolver.NoAnswer:
        points['IPV6 support'] = False

    # Definition of SPF and DMARC
    try:
        spf = check_domains([domain])

        # 7 DNSSEC implementado
        dnssec = spf['dnssec']
        points['dnssec'] = dnssec
        points['ns warnings'] = spf['ns']['warnings']
        points['addressses'] = spf['mx']['hosts'][0]['addresses']
        points['dmarc'] = spf['dmarc']['record']
        
        # 4 TTL response
        points['tls support'] = spf['mx']['hosts'][0]['tls']
        points['starttls support'] = spf['mx']['hosts'][0]['starttls']
        points['mx warnings'] = spf['mx']['warnings']
        points['SPF support'] = True

    except:
        points['SPF support']  = False

    # consistencia en SOA
    try: 
        data = dns.resolver.query(domain, "SOA")
        
        points['SOA consistency'] = True
        for rdata in data:
            points['SOA serial'] = rdata.serial
            points['SOA refresh'] = rdata.refresh
            points['SOA expire'] = rdata.expire
            points['SOA mname'] = rdata.mname
    except dns.resolver.NoAnswer:
        points['SOA consistency'] = False

    # Allow_transferences
    nm = nmap.PortScanner()
    data = nm.scan(ip, arguments="-O")

    if ip in data:
        if 'osclass' in nm[ip]:
            for osclass in nm[ip]['osclass']:
                print('OsClass.type : ' + osclass['type'])
                print('OsClass.vendor : '+ osclass['vendor'])
                print('OsClass.osfamily : '+ osclass['osfamily'])
                print('OsClass.osgen : ' + osclass['osgen'])
                print('OsClass.accuracy : ' + osclass['accuracy'])
                print('')

    # version del servidor
    try:
        response = dns.resolver.query(domain ,dns.rdatatype.NS)

        nsname = response.rrset[0].to_text()
        response = dns.resolver.query(nsname,dns.rdatatype.A)
        nsaddr = response.rrset[0].to_text()
        request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)

        # send the query
        response = dns.query.udp(request,nsaddr)
        points['DNSSEC'] = True

        if response.rcode() != 0:
            points['DNSSEC'] = False
    except:
        points['DNSSEC'] = False

    count = 0
    for i in points:
        print(i+ ' check result: ' + str(points[i]))
        if points[i] == False:
            count += 1
    
    print('Los puntos de peligro detectados: ' + str(count))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--domain', metavar='<domain name>',
                        help='domain to check', required=True)
    args = parser.parse_args()
    
    domain = args.domain
    
    process(domain)
    sys.exit(0)