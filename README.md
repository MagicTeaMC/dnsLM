# dnsLM
dnsLM: Where AI meets DNS—because even domains deserve a little intelligence!
## About
This project uses Llama 3.3 and Groq's super-fast infrastructure to create a DNS server that's almost as quick as the real thing. I designed a prompt to help the LLM guess the correct IP address for a given domain. However, since the LLM is basically guessing based on what it already knows, it only gets the IP right about 10% of the time.
## Setup
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