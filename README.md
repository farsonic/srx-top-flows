# srx-top-flows
Return a list of the top open security flows on a Juniper SRX firewall

Often through an SRX firewall there are users downloading large files. This script is deisnged to quickly identify the top flow entries listed by Session-ID, Minutes downloading as well as Megabytes In/Out. Additionally the script performs a whois on the destination IP Addresses as well as a GeoIP lookup to help identify the source. 

# Install
```
pip install jxmlease
pip install lxml
pip install junos-eznc 
pip install geoip
pip install netaddr
```

# Usage
```
./Session-Report.py
ID        Minutes   Application name              MB Up     MB Down   Source|Destination pair
=============================================================================================================================================================================
11366     4         junos:HTTP                    0.00      2.00      192.168.0.100<-->90.130.74.113         SE-TELE2-SERVERS              SE   Europe/Stockholm    
11367     4         junos:HTTP                    1.00      47.00     192.168.0.100<-->150.101.135.3         TPA                           AU   None                
11368     4         junos:HTTP                    0.00      18.00     192.168.0.100<-->50.116.14.9           LINODE-US                     US   America/New_York    
11369     4         junos:HTTP                    0.00      1.00      192.168.0.100<-->90.130.74.153         SE-TELE2-SERVERS              SE   Europe/Stockholm    
11370     4         junos:HTTP                    0.00      3.00      192.168.0.100<-->90.130.74.155         SE-TELE2-SERVERS              SE   Europe/Stockholm    
11371     4         junos:HTTP                    0.00      4.00      192.168.0.100<-->50.116.57.237         LINODE-US                     US   America/New_York   
```
