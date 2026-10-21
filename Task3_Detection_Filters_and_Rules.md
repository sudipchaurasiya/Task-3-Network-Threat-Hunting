# Wireshark Display Filters

## Filter 1: Executable download
Filter:
ip.addr == 107.175.82.242 && tcp.port == 9000

Purpose:
Shows traffic involving the server that delivered runner_ilove.exe.

Limitation:
A connection to this IP and port alone does not prove malicious activity.

## Filter 2: Unusual HTTP requests
Filter:
http.host == "holtandberyl.com" && (http.request.uri == "/prw" || http.request.uri == "/crv")

Purpose:
Shows the two observed HTTP requests and supports review of their redirects.

Limitation:
Short URL paths and redirects are not proof of malicious activity. HTTPS content is encrypted.

## Filter 3: DNS error responses
Filter:
dns.flags.response == 1 && dns.flags.rcode != 0

Purpose:
Shows DNS responses with error codes, including NXDOMAIN.

Limitation:
Failed DNS lookups can be normal. Investigate context before raising an alert.

# Defensive Detection Rule 1 (Sigma-style pseudocode)
title: Executable Download Over Unusual HTTP Port
status: experimental
logsource:
  category: proxy
detection:
  selection:
    destination_ip: '107.175.82.242'
    destination_port: 9000
    http_method: 'GET'
    url_path: '/wilow/runner_ilove.exe'
  condition: selection
level: high
note: Based on this capture. Validate against trusted proxy logs before deployment.

# Defensive Detection Rule 2 (Sigma-style pseudocode)
title: Repeated DNS Negative Responses
status: experimental
logsource:
  category: dns
detection:
  selection:
    query_name: 'wpad.natureforce.com'
    response_code: 'NXDOMAIN'
  condition: selection
level: low
note: This is a monitoring lead, not a malware verdict. WPAD discovery can be normal.
