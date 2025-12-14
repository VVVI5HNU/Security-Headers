# Security Headers Checker

---

## 🔍 What This Tool Checks

The script checks for commonly recommended HTTP security headers, including (but not limited to):

- `Content-Security-Policy (CSP)`
- `Strict-Transport-Security (HSTS)`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `X-XSS-Protection`

If a header is missing or misconfigured, the tool highlights it in the output.

---

## ⚙️ Prerequisites

- Python 3.x
- Internet access to reach the target web application
- Required Python dependencies (listed in `requirements.txt`, if applicable)

---

## 📥 Installation

1. Clone the repository:
```
git clone https://github.com/VVVI5HNU/security-headers.git
cd security-headers
```

---

## ▶️ Usage

Run the script against a target URL:

```
python security-headers.py -u https://example.com
```

---

## 🧠 Use Cases

- Web Application VAPT assessments
- Security hardening validation
- Developer self-checks before deployment
- Learning and understanding HTTP security headers

---

