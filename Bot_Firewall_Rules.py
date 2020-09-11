## Author:
##		Charles V. Frank Jr.
##		charles.frank@trojans.dsu.edu
## 
## Date:
##		Sept 9, 2020
## -------------------------------------------------------------------------------------------	
## Module:
##      Bot_Firewall_Rules.py
## -------------------------------------------------------------------------------------------
## Purpose:
##      Detects bots form PCAP file, based upon SYN packets 
##      Creates firewall rules to block bot traffic
##
## Bot Scanning dataset from:
##      https://www.impactcybertrust.org/dataset_view?idDataset=740
## -------------------------------------------------------------------------------------------
## Execute:
##     Bot_Firewall_Rules <PCAP file> 

## OS
import os

## Scapy
from scapy.all import *

## Pandas dataframe
import pandas as pd

## Needed for commandline option
import sys

##
## This function analyzes the PCAP file from the dataset
## Parameters:
##  pcap_file - PCAP file
##

def bot_firewall_rules(pcap_file): 
    print "========================================================================="

    ## Initialize needed lists
    ip_src_list = []

    ## Read the PCAP file 
    packets = rdpcap(pcap_file)
    
    ## Go thru each packet
    for each_packet in packets:

        ## Make sure we have a TCP SYN packet on telnet ports 23, 2323
        if (each_packet[IP].proto = "TCP" and each_packet[TCP].flags ="S" and 
           (each_packet[TCP].dport=23 or each_packet[TCP].dport=2323))
       
            ## If src IP is unique
            if ( each_packet[IP].src not in ip_src_list )

                ## put in src list
                ip_src_list.append(each_packet[IP].src)

                ## print firewall rules
                rule_head = "iptables --A INPUT"
                rule_body = " --s " + each_packet[IP].src + "/32"
                rule_tail = " --j DROP"

                ## print rule 1
                print rule_head + rule_body + rule_tail

                ## print rule 2
                rule_body = " --mac-source " + packet[Ether].src
                print rule_head + rule_body + rule_tail
    
    return 0

## main function
def main():

    ## PCAP file provided on the commandline
    p_file = sys.argv[1]

    ## Call function to generate frewall rules
    bot_firewall_rules(p_file)

    
if __name__ == "main":
    main()