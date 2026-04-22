# Sample Repository

This repository contains a collection of web application components for static analysis and scanner testing.

## Structure

```
dummy-repo/
├── website/                    # Frontend JavaScript application
│   ├── index.html             # Main page
│   ├── login.html             # Login page
│   ├── style.css              # Stylesheet
│   └── app.js                 # Application logic
├── python-tool/               # Backend Python application
│   ├── app.py                 # Flask web application
│   ├── database.py            # Database access layer
│   ├── utils.py               # Utility functions
│   ├── config.py              # Application configuration
│   └── requirements.txt       # Python dependencies
├── sonar-project.properties   # SonarCloud configuration
└── README.md
```

## Overview

### JavaScript / Website

| Category | Examples |
|----------|----------|
| DOM manipulation | `innerHTML`, `document.write()` |
| Authentication | API keys, credential handling |
| URL handling | Redirects, hash-based routing |
| Object operations | Object merging, prototype access |
| Input validation | Email validation patterns |

### Python Application

| Module | Description |
|--------|-------------|
| `database.py` | Database queries and user management |
| `utils.py` | File I/O, command execution, hashing utilities |
| `app.py` | Flask routes: login, search, file download, XML parsing |
| `config.py` | Application settings and credentials |

## Setup

### Quick Start

1. **Clone** this repository
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

## Testing with RAVEN

1. Push this repository to GitHub
2. Ensure it is analysed in SonarCloud
3. Start RAVEN: `docker compose up -d`
4. Open the UI at http://localhost:3000
5. Enter SonarCloud credentials and the repository URL
6. View the consolidated scan report
