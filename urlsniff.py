# coding=UTF-8

import argparse
from time import gmtime, strftime
from scapy.all import *
from scapy.layers import http

# Additional arguments for URL Sniffer
parser = argparse.ArgumentParser(description='A simple Python tool to sniff URL\'s fron network traffic')
parser.add_argument('-i','--interface', help='Interface to sniff packets', required=False)
parser.add_argument('-e','--external', help='Path to external PCAP file to scan', required=False)
args = vars(parser.parse_args())

# Look for packets with HTTP info and filter out client and URL info
def breakdown(pkt):
    if pkt.haslayer(http.HTTPRequest):   
        URL = "http://" + pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path
        print "{3} - {1} [{0}] >> {2}".format(pkt[Ether].src, pkt[IP].src, URL, strftime("[%Y-%m-%d :: %H:%M:%S]", gmtime()))

# Error check to ensure proper usage of parameters
if args['external'] == None and args['interface'] == None:
    print "One input source is needed to run"
    quit()
if args['external'] != None and args['interface'] != None:
    print "Only one input source can be used at a time"
    quit()

# Open external pcap file if one is provided
if args['external'] != None:
    packets = rdpcap(args['external'])
    for p in packets:
        breakdown(p)
# Sniff packets on interface running on port 80
else:
    sniff(filter='port 80', prn=breakdown, store=0, iface=args['interface'])