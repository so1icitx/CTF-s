# Wireshark Analysis Writeup Carnage [here](https://tryhackme.com/room/c2carnage)
## Scenario Overview

Eric Fischer at Bartell Ltd opened a Word document with an enabled macro, triggering suspicious outbound connections detected by the SOC’s endpoint agent. A PCAP file was retrieved for analysis to identify malicious activities, including downloaded files, Cobalt Strike C2 servers, and malspam. The goal is to answer specific questions about the traffic while providing a reusable methodology for similar investigations.

**Note**: Do not interact with any domains or IP addresses in this challenge. All URLs and IPs are defanged (e.g., `example[.]com`) for safety.

### 1. First HTTP Connection to Malicious IP

**Question**: What was the date and time for the first HTTP connection to the malicious IP? (Format: yyyy-mm-dd hh:mm:ss)

**Steps**:
- Filter HTTP traffic: `http`.
- Sort by `Time` column (UTC).
- Identify the first HTTP packet (e.g., Frame 1735 in the walkthrough).
- Check Packet Details > Frame > Arrival Time.

**Filter**: `http`

**Answer**: 2021-09-24 16:44:38

**Explanation**: The filter `http` isolates HTTP traffic, and the first packet’s timestamp provides the answer. Malicious IPs are often identified later via domain or GET request analysis.

### 2. Name of Downloaded Zip File

**Question**: What is the name of the zip file that was downloaded?

**Steps**:
- Filter HTTP GET requests: `http.request.method=="GET"`.
- Locate the first GET request (e.g., Frame 1735).
- Check Packet Details > Hypertext Transfer Protocol > Request URI for the file name.

**Filter**: `http.request.method=="GET"`

**Answer**: documents[.]zip

**Explanation**: GET requests often indicate file downloads. The URI in the first GET reveals the zip file name, a common malware delivery method.

### 3. Domain Hosting the Malicious Zip File

**Question**: What was the domain hosting the malicious zip file?

**Steps**:
- Use the same GET request from Frame 1735.
- Check Packet Details > Hypertext Transfer Protocol > Host.

**Filter**: `http.request.method=="GET"`

**Answer**: attirenepal[.]com

**Explanation**: The `Host` header in the GET request identifies the domain serving the zip file, a key indicator of malicious infrastructure.

### 4. File Name Inside the Zip File (Without Downloading)

**Question**: Without downloading the file, what is the name of the file in the zip file?

**Steps**:
- Locate the HTTP response to the GET request (e.g., Frame 2173).
- Follow the TCP stream: Right-click > Follow > TCP Stream.
- In the stream, search for a file name (often near the end).
- Alternatively, check Packet Details > Hex pane for strings resembling a file name (e.g., `.xls`).

**Filter**: `http.response`

**Answer**: chart-1530076591[.]xls

**Explanation**: The response packet contains the zip file’s contents. The `.xls` file name in the hex or stream suggests a malicious macro-enabled document, aligning with the scenario.

### 5. Webserver Name of Malicious IP

**Question**: What is the name of the webserver of the malicious IP from which the zip file was downloaded?

**Steps**:
- Use the response packet (Frame 2173).
- Check Packet Details > Hypertext Transfer Protocol > Server.

**Filter**: `http.response`

**Answer**: LiteSpeed

**Explanation**: The `Server` header identifies the webserver software, often LiteSpeed or Apache for malicious hosts.

### 6. Webserver Version

**Question**: What is the version of the webserver from the previous question?

**Steps**:
- In the same response packet, check Packet Details > Hypertext Transfer Protocol > X-Powered-By.

**Filter**: `http.response`

**Answer**: PHP/7.2.34

**Explanation**: The `X-Powered-By` header reveals the server’s PHP version, often included in LiteSpeed responses.

### 7. Three Domains Involved in Malicious File Downloads

**Question**: Malicious files were downloaded from multiple domains. What were the three domains involved?

**Steps**:
- Filter TLS Client Hello packets to identify domains: `tls.handshake.type==1`.
- Sort by `Time` and focus on packets after 16:44:38 (first HTTP connection).
- Narrow to the timeframe 16:45:11–16:45:30 UTC (per walkthrough hint).
- Check Packet Details > TLS > Handshake Protocol > Extension: server_name for suspicious domains.
- Cross-reference with VirusTotal for malicious indicators.

**Filter**: `tls.handshake.type==1`

**Answer**: finejewels[.]com[.]au, thietbiagt[.]com, new[.]americold[.]com

**Explanation**: TLS Client Hello packets reveal domains via SNI (Server Name Indication). The timeframe reduces noise, and suspicious domains are identified by their context (e.g., non-standard TLDs, unrelated to legitimate traffic like Microsoft Edge).[](https://medium.com/%40parkerbenitez/wireshark-traffic-and-malware-analysis-2a5da9b5a610)

### 8. Certificate Authority for First Domain

**Question**: Which certificate authority issued the SSL certificate to the first domain (finejewels[.]com[.]au)?

**Steps**:
- Filter for TLS Server Hello from the first domain: `tls.handshake.type==2 and tls.handshake.extensions_server_name contains "finejewels"`.
- Follow the TCP stream: Right-click > Follow > TCP Stream.
- Locate the certificate details in the stream or Packet Details > TLS > Handshake Protocol > Certificate > Issuer.

**Filter**: `tls.handshake.type==2`

**Answer**: GoDaddy

**Explanation**: The Server Hello contains the SSL certificate, with the issuer field identifying the certificate authority. GoDaddy is a common CA for malicious domains.[](https://medium.com/%40enyel.salas84/tryhackme-wireshark-traffic-analysis-592bf06df0b1)

### 9. Cobalt Strike Server IP Addresses

**Question**: What are the two IP addresses of the Cobalt Strike servers? Confirm via VirusTotal Community tab. (Sequential order)

**Steps**:
- Filter for frequent HTTP GET/POST requests, typical of C2 traffic: `http.request.method=="GET" or http.request.method=="POST"`.
- Use Statistics > Conversations > TCP to identify IPs with high packet counts.
- Sort by IP address and check for recurring connections post-16:44:38.
- Verify IPs on VirusTotal (Community tab) for Cobalt Strike C2 labels.

**Filter**: `http.request.method=="GET" || http.request.method=="POST"`

**Answer**: 185[.]106[.]96[.]158, 185[.]125[.]204[.]174

**Explanation**: Cobalt Strike C2 servers exhibit frequent HTTP requests. Conversations highlight IPs with persistent communication, and VirusTotal confirms their malicious nature.[](https://www.cyberly.org/en/how-do-you-identify-malicious-packets-in-wireshark/index.html)

### 10. Host Header for First Cobalt Strike IP

**Question**: What is the Host header for the first Cobalt Strike IP (185[.]106[.]96[.]158)?

**Steps**:
- Filter for HTTP requests to the IP: `ip.addr==185.106.96.158 and http`.
- Check Packet Details > Hypertext Transfer Protocol > Host.

**Filter**: `ip.addr==185.106.96.158 and http`

**Answer**: oscp[.]verisign[.]com

**Explanation**: The `Host` header in HTTP requests to the C2 server reveals the domain used, often mimicking legitimate services (e.g., Verisign).

### 11. Domain Name for First Cobalt Strike IP

**Question**: What is the domain name for the first Cobalt Strike IP (185[.]106[.]96[.]158)? Confirm via VirusTotal.

**Steps**:
- Use VirusTotal to search the IP (185[.]106[.]96[.]158).
- Check Historical WHOIS or Relations tab for associated domains.
- Verify Cobalt Strike C2 status in the Community tab.

**Answer**: survmeter[.]live

**Explanation**: VirusTotal’s WHOIS data links the IP to a domain, confirmed as a C2 server via community reports.

### 12. Domain Name for Second Cobalt Strike IP

**Question**: What is the domain name for the second Cobalt Strike IP (185[.]125[.]204[.]174)? Confirm via VirusTotal.

**Steps**:
- Search the IP on VirusTotal.
- Check Community tab for domain associations and C2 confirmation.

**Answer**: securitybusinpuff[.]com

**Explanation**: The Community tab directly provides the domain, validated as a Cobalt Strike C2 server.

### 13. Domain Name of Post-Infection Traffic

**Question**: What is the domain name of the post-infection traffic?

**Steps**:
- Filter for HTTP POST requests, common in post-infection C2 communication: `http.request.method=="POST"`.
- Check Packet Details > Hypertext Transfer Protocol > Host for the domain.

**Filter**: `http.request.method=="POST"`

**Answer**: maldivehost[.]net

**Explanation**: POST requests indicate data exfiltration or C2 check-ins. The `Host` header identifies the malicious domain.[](https://mahmoud-shaker.gitbook.io/dfir-notes/network-forensics)

### 14. First Eleven Characters Sent to Malicious Domain

**Question**: What are the first eleven characters that the victim host sends out to the malicious domain (maldivehost[.]net)?

**Steps**:
- Filter for POST requests to the domain: `http.request.method=="POST" and http.host contains "maldivehost"`.
- Follow the TCP stream: Right-click > Follow > TCP Stream.
- Extract the first 11 characters of the client’s data.

**Filter**: `http.request.method=="POST" and http.host contains "maldivehost"`

**Answer**: zLIisQRWZI

**Explanation**: The TCP stream reveals the payload sent to the C2 server, often encoded data or identifiers.

### 15. Length of First Packet to C2 Server

**Question**: What was the length for the first packet sent out to the C2 server?

**Steps**:
- Filter for packets to the first Cobalt Strike IP: `ip.dst==185.106.96.158`.
- Sort by `Time` and select the first packet.
- Check Packet Details > Frame > Length.

**Filter**: `ip.dst==185.106.96.158`

**Answer**: 281

**Explanation**: The `Length` field in the first packet to the C2 server provides the answer, indicating the initial communication size.

### 16. Server Header for Malicious Domain

**Question**: What was the Server header for the malicious domain (maldivehost[.]net)?

**Steps**:
- Filter for HTTP responses from the domain: `http.response and http.host contains "maldivehost"`.
- Follow the TCP stream to locate the `Server` header.

**Filter**: `http.response and http.host contains "maldivehost"`

**Answer**: nginx

**Explanation**: The `Server` header in the response identifies the webserver (nginx), common in C2 infrastructure.[](https://mahmoud-shaker.gitbook.io/dfir-notes/network-forensics)

### 17. DNS Query for IP Check API

**Question**: What was the date and time when the DNS query for the IP check domain occurred? (Format: yyyy-mm-dd hh:mm:ss UTC)

**Steps**:
- Filter for DNS queries containing “api”: `dns and dns.qry.name contains "api"`.
- Sort by `Time` and locate the relevant query (e.g., api[.]ipify[.]org).
- Check Packet Details > Frame > Arrival Time.

**Filter**: `dns and dns.qry.name contains "api"`

**Answer**: 2021-09-24 17:00:04

**Explanation**: Malware often queries APIs like ipify to determine the victim’s IP. The DNS filter isolates this query.[](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)

### 18. Domain in DNS Query

**Question**: What was the domain in the DNS query from the previous question?

**Steps**:
- Use the same DNS query packet.
- Check Packet Details > Domain Name System > Queries > Name.

**Filter**: `dns and dns.qry.name contains "api"`

**Answer**: api[.]ipify[.]org

**Explanation**: The query name confirms the API domain, a legitimate service abused by malware.

### 19. First MAIL FROM Address in Malspam

**Question**: What was the first MAIL FROM address observed in the traffic?

**Steps**:
- Filter for SMTP traffic containing “MAIL FROM”: `smtp and frame contains "MAIL FROM"`.
- Sort by `Time` and select the first packet.
- Check Packet Details > SMTP > Command Line for the email address.

**Filter**: `smtp and frame contains "MAIL FROM"`

**Answer**: farshin@mailfa[.]com

**Explanation**: SMTP traffic reveals malspam activity. The `MAIL FROM` field identifies the sender, often a spoofed or malicious address.[](https://www.packtpub.com/en-us/learning/how-to-tutorials/wireshark-analyze-malicious-emails-in-pop-imap-smtp/)

### 20. Number of SMTP Packets

**Question**: How many packets were observed for the SMTP traffic?

**Steps**:
- Filter for SMTP traffic: `smtp`.
- Check the Wireshark status bar for the total packet count.

**Filter**: `smtp`

**Answer**: 1439

**Explanation**: The `smtp` filter isolates email traffic, and the packet count reflects malspam volume.[](https://unit42.paloaltonetworks.com/using-wireshark-display-filter-expressions/)

