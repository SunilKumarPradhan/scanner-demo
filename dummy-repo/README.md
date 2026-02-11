# Dummy Repository for SonarCloud Testing

This repository contains intentionally vulnerable code for testing SonarCloud static analysis capabilities.

**⚠️ DO NOT USE THIS CODE IN PRODUCTION! ⚠️**

This is a test repository designed to help validate security scanning tools.

## Structure

```
dummy-repo/
├── website/                    # Frontend with JavaScript vulnerabilities
│   ├── index.html             # XSS, eval(), hardcoded keys
│   ├── login.html             # Credential storage vulnerabilities
│   ├── style.css              # CSS code smells
│   └── app.js                 # Multiple JS security issues
├── python-tool/               # Backend Python application
│   ├── app.py                 # Flask app with OWASP Top 10 issues
│   ├── database.py            # SQL injection demonstrations
│   ├── utils.py               # Command injection, path traversal
│   ├── config.py              # Hardcoded credentials showcase
│   └── requirements.txt       # Outdated/vulnerable dependencies
├── sonar-project.properties   # SonarCloud configuration
└── README.md
```

## Intentional Vulnerabilities

### JavaScript/Website Vulnerabilities

| Category | Examples |
|----------|----------|
| XSS | `innerHTML` with user input, `eval()`, `document.write()` |
| Credential Exposure | Hardcoded API keys, passwords in localStorage |
| Unsafe eval | `eval()` with URL hash, postMessage data |
| Prototype Pollution | Object merge without `__proto__` check |
| ReDoS | Catastrophic backtracking in email regex |
| Open Redirect | Unvalidated URL redirects |
| Code Smells | Unused variables, duplicate functions, empty functions |

### Python Vulnerabilities (OWASP Top 10)

| Vulnerability | File | Description |
|---------------|------|-------------|
| SQL Injection | `database.py` | String formatting in queries |
| Command Injection | `utils.py`, `app.py` | `os.system()`, `subprocess` with user input |
| SSTI | `app.py` | `render_template_string()` with user data |
| Path Traversal | `utils.py` | Unvalidated file paths |
| SSRF | `app.py`, `utils.py` | Unvalidated URL fetching |
| Insecure Deserialization | `app.py` | `pickle.loads()` with user data |
| Hardcoded Credentials | `config.py` | Passwords, API keys, tokens |
| Weak Cryptography | `app.py`, `utils.py` | MD5, SHA1, `random` module |
| XXE | `app.py` | XML parsing without protection |
| Open Redirect | `app.py` | Unvalidated redirect URLs |

### Code Quality Issues

- **Cyclomatic Complexity**: Deeply nested conditionals
- **Duplicate Code**: Repeated functions
- **Dead Code**: Unused functions and variables
- **Magic Numbers**: Unexplained numeric constants
- **Too Many Parameters**: Functions with excessive arguments
- **Empty Methods**: Placeholder functions
- **Outdated Dependencies**: Known vulnerable package versions

## SonarCloud Setup

### Quick Start

1. **Fork/Clone** this repository to GitHub
2. **Create project** in [SonarCloud](https://sonarcloud.io)
3. **Import repository** from GitHub
4. **Run analysis** (automatic on push or manual)
5. **View findings** in SonarCloud dashboard

### Configuration

The `sonar-project.properties` file configures:
- Project key and organization
- Source directories
- File exclusions
- Language settings

### Expected Findings

After analysis, SonarCloud should detect:
- **50+ Security Vulnerabilities**
- **30+ Bugs**
- **100+ Code Smells**
- **Security Hotspots** for manual review

## Testing with RAVEN Scan

1. Push this repository to GitHub (must be public)
2. Ensure it's analyzed in SonarCloud
3. Start RAVEN Scan: `docker compose up -d`
4. Open UI at http://localhost:3000
5. Enter SonarCloud credentials
6. Enter this repo's GitHub URL
7. View consolidated vulnerability report

## Disclaimer

This code is **intentionally insecure** for educational and testing purposes only. Never deploy this code or use these patterns in real applications.
