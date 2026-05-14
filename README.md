# SecureBank — Banking Attack Lab

Information Security Semester Project | FAST NUCES

## Setup

```bash
pip install flask pycryptodome
python app.py
```

Open: http://localhost:5000

## Demo Credentials

| User  | Password | Role  |
|-------|----------|-------|
| admin | admin123 | admin |
| alice | user123  | user  |
| bob   | user123  | user  |

## Attack Demos

### SQL Injection
- Login page → Switch to Attack Mode
- Username: `' OR '1'='1` | Password: anything
- Observe raw SQL query exposed on screen

### XSS (Cross-Site Scripting)
- Go to Messages → Attack Mode
- Post: `<script>alert('XSS!')</script>`
- Switch to Secure Mode → same input is escaped

### CSRF (Cross-Site Request Forgery)
- Dashboard → Attack Mode → Open Forged Page link
- Click the fake "Claim Voucher" button
- In Vulnerable Mode: transfer goes through
- In Secure Mode: blocked by CSRF token validation

### Crypto Lab
- AES-128 vs DES encryption/decryption
- SHA-512 password hashing demo

### Access Control
- Login as alice → try visiting /admin → 403
- Login as admin → /admin accessible

## Security Topics Covered
1. SQL Injection + Defense
2. XSS (Stored) + Sanitization
3. CSRF + Token Defense
4. Authentication + SHA-512 Hashing
5. AES-128 Encryption
6. DES Weakness Comparison
7. Role-Based Access Control
