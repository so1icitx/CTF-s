# TShark Challenge I: Teamwork - Investigating a Suspicious Domain


## Investigation Process

### Step 1: Identify Contacted Domains

To investigate contacted domains, start by analyzing TCP endpoints to identify hosts communicating over HTTP (port 80) or HTTPS (port 443), common for web traffic. Use the following TShark command to list TCP endpoints:

```bash
tshark -r teamwork.pcap -z endpoints,tcp -q
```

**Explanation**: The `-z endpoints,tcp` option generates a summary of TCP endpoints, showing IPs, ports, packet counts, and byte volumes. The `-q` flag suppresses packet details, focusing on statistics. The output highlights `184[.]154[.]127[.]226` on port 80 with 103,529 Tx Bytes, indicating significant data transfer, which is suspicious for a potential malicious domain.

**Screenshot**:
![TCP Endpoints Output](./screenshots/tcp_endpoints.png)

Next, extract HTTP hostnames to identify domains:

```bash
tshark -r teamwork.pcap -Y "http.host" -T fields -e http.host | sort | uniq
```

**Explanation**: The `-Y "http.host"` filter selects packets with an HTTP host header, and `-T fields -e http.host` extracts the hostname. Piping to `sort | uniq` removes duplicates. The output reveals a suspicious domain:

```
www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com
```

**Analysis**: The domain mimics PayPal’s legitimate URL (`www[.]paypal[.]com`) but appends a deceptive path and subdomain (`timeseaways[.]com`), suggesting a phishing attempt.

**Screenshot**:
![HTTP Host Output](./screenshots/http_host.png)

To confirm the domain’s context, inspect the HTTP request packet:

```bash
tshark -r teamwork.pcap -Y "http.host" -x
```

**Explanation**: The `-x` option displays packet details in hex and ASCII, revealing the full HTTP GET request. Decoding the URL in CyberChef confirms the malicious domain: `hxxp[://]www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/`.

**Screenshot**:
![HTTP Packet Hex Output](./screenshots/http_packet_hex.png)

### Step 2: Analyze Domains with VirusTotal

Submit the domain `www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com` to **VirusTotal** for analysis. VirusTotal flags this domain as **malicious/suspicious**, confirming the threat.

**Findings from VirusTotal**:
- **Full URL**: `hxxp[://]www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/`
- **First Submission**: `2017-04-17 22:52:53 UTC`
- **Impersonated Service**: PayPal (evident from the domain’s mimicry of `www[.]paypal[.]com`)
- **IP Address**: `184[.]154[.]127[.]226`

**Explanation**: VirusTotal’s analysis indicates the domain is designed to deceive users into believing it’s a legitimate PayPal account recovery page. The submission date shows when it was first reported, and the IP matches the high-traffic endpoint from the TCP endpoints, linking it to the suspicious activity.

**Screenshots**:
![VirusTotal URL Analysis](./screenshots/vt_url_analysis.png)
![VirusTotal IP Details](./screenshots/vt_ip_details.png)

### Step 3: Extract Email Address

To find the email address used in the malicious activity, focus on HTTP POST requests, which often transmit form data like credentials. Use the following command:

```bash
tshark -r teamwork.pcap -Y "http.request.method matches POST" -T fields -e http.request.uri -e http.host -e http.file_data | grep user
```

**Explanation**: The `-Y "http.request.method matches POST"` filter selects POST requests, and `-T fields` extracts the request URI, host, and form data. Grepping for `user` targets form fields likely containing an email. The output shows:

```
/inc/login.php www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com user=johnny5alive[at]gmail[.]com&pass=johnny5alive&...
```

**Email Address**: `johnny5alive[at]gmail[.]com`

**Analysis**: The POST request to `/inc/login.php` on the malicious domain submits an email and password, indicating a phishing attempt to capture credentials. Additional form data (e.g., browser type, OS) suggests device fingerprinting.

**Screenshot**:
![HTTP POST Form Data](./screenshots/http_post_form.png)


