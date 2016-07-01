#!/usr/bin/python

from jxmlease import Parser
from lxml import etree
from jnpr.junos import Device
from ipwhois import IPWhois
from pprint import pprint
from geoip import geolite2
from netaddr import *


### Update IP, Username and password fields ###
srx = 'SRX-IP-ADDRESS'
user = 'USERNAME'
password = 'PASSWORD'

myparser = Parser()

dev = Device(host=srx,user=user,password=password)
dev.open()

flow_data = etree.tostring(dev.rpc.get_flow_session_information())
jflows = myparser(flow_data)
flow_sessions = jflows['flow-session-information']['flow-session']

print '{0:10}{1:<10}{2:<30}{3:<10}{4:<10}{5:<22}'.format("ID", "Minutes","Application name", "MB Up", "MB Down","Source|Destination pair")
print "============================================================================================================================================================================="

for element in flow_sessions: 
   in_pckt_cnt = 0
   in_byte_cnt = 0 
   out_pckt_cnt = 0
   out_byte_cnt = 0 
   for flow_info in element['flow-information']:
     direction = str(flow_info['direction'])
     while direction == "In":
      in_pckt_cnt += int(flow_info['pkt-cnt'])
      in_byte_cnt += int(flow_info['byte-cnt'])
      src_ip = str(flow_info['source-address'])
      dst_ip = str(flow_info['destination-address'])
      in_mb_cnt = in_byte_cnt/1024/1024
      break
     while direction == "Out":
      out_pckt_cnt += int(flow_info['pkt-cnt'])
      out_byte_cnt += int(flow_info['byte-cnt'])
      out_mb_cnt = out_byte_cnt/1024/1024
      break
      
   if in_mb_cnt or out_mb_cnt >= 1:
     country = "Private"
     timezone = ""
     obj = IPWhois(dst_ip)
     results = obj.lookup_rdap(depth=1)
     name = (results['network']['name'])
     if IPAddress(dst_ip).is_private() <> True: 
      iplookup = geolite2.lookup(dst_ip)
      country = iplookup.country
      timezone = iplookup.timezone
     print '{0:10}{1:<10}{2:<30}{3:<10.2f}{4:<10.2f}{5:>13}{6:<1}{7:<22}{8:<30}{9:<5}{10:<20}'.format(element['session-identifier'], int(element['duration'])/60,element['dynamic-application-name'], in_mb_cnt, out_mb_cnt,src_ip,"<-->",dst_ip,name,country,timezone)

dev.close()

