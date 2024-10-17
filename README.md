# Subdomain Decoder  

While practicing for the upcoming National Cyber League (NCL) season, I came across a problem that required me to extract exfiltrated data from DNS queries within a pcap file.
Data was being exfilitrated through the subdmomains of the DNS queries and were base64 encoded.
I took this opportunity to practice my scripting and made a mini project out of it.  

> **NOTE**: This is a script specific to the CTF problem I was solving and needs to be modified depending on use case. 🤓

This script:
- Processes a pcap file to extract subdomains, concatenates them, and performs Base64 decoding.
- Replaces URL-safe Base64 characters (e.g. `-`, `_`) with standard Base64 characters (`+`, `/`)
- If the decoded data turns out to be a zip file, the script saves it, unzips it, and extracts a `flag.txt` file. 

## Use:
```python3
python3 subdomain_decoder.py example.pcapng
```

![subdomain_decoder_use](https://github.com/user-attachments/assets/22b58f53-0b91-4116-95b4-c440c6bc47cb)
No spoilers! 😆






