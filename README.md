# dnsLM
dnsLM: Where AI meets DNS—because even domains deserve a little intelligence!
## setup
1. Generating self-signed certificate
```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```
2. Run server
```
python3 main.py
```
3. Test it with [dnslookup](https://github.com/ameshkov/dnslookup)
```
VERIFY=0 dnslookup google.com https://127.0.0.1/dns-query
```