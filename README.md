# HiddenOSINT

**HiddenOSINT** is a powerful darkweb intelligence gathering tool developed for digital forensics professionals to collect and analyze information about .onion domains.

## Features

- Secure access to .onion domains through the Tor network
- Domain reachability checks and status monitoring
- HTTP header collection and security header analysis
- Server identification and technology detection
- Extraction of meta information (title, description, keywords)
- Collection and analysis of links, images, and forms
- Email address extraction from page content
- Framework and technology detection
- Subpage scanning capabilities
- Security header analysis and recommendations
- Page content fingerprinting (MD5, SHA256)
- Results saved in both JSON and HTML formats
- User-friendly command-line interface with extensive options

## Requirements

- Python 3.6+
- Tor service running on the local machine (typically on port 9050)
- Python dependencies (listed in the requirements.txt file)

## Installation

1. Clone or download the repository:

```bash
git clone https://github.com/username/HiddenOSINT.git
cd HiddenOSINT
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Start the Tor service (example commands):

**Windows:**
```
# If Tor Browser is installed, start the Tor Browser
# Alternatively, a separate Tor service can be installed
```

**Linux:**
```bash
sudo service tor start
# or
sudo systemctl start tor
```

## Usage

Basic usage:

```bash
python hidden_osint.py example123abc.onion
```

With additional parameters:

```bash
python hidden_osint.py example123abc.onion --output results --timeout 60 --subpages --max-subpages 10
```

### Parameters

- `domain`: The .onion domain to scan (required)
- `-o, --output`: Directory to save results (default: "results")
- `-t, --timeout`: Request timeout in seconds (default: 30)
- `-s, --subpages`: Enable scanning of subpages (internal links)
- `-m, --max-subpages`: Maximum number of subpages to scan (default: 5)
- `--no-html`: Disable HTML report generation
- `--new-identity`: Request a new Tor identity before scanning

## Outputs

Results are saved to the specified output directory in both JSON and HTML formats:

```
results/
  ├── example123abc_info.json
  └── example123abc_info.html
```

The JSON output includes the following information:

- Domain information and scan date
- Reachability status and response time
- HTTP status code and headers
- Security headers analysis
- Server information and technologies detected
- Page title, description, and keywords
- Framework and technology detection
- Links, images, and forms on the page
- Email addresses found in the content
- Page content fingerprints (hashes)
- Subpage information (if scanning enabled)

The HTML report provides a user-friendly presentation of all collected data with formatting and visual indicators for security issues.

## Security Notes

- Use this tool only for legal research and digital forensics purposes
- Ensure that your activities on the Darkweb remain within legal boundaries
- Accessing illegal content, even for research purposes, may have legal consequences
- The tool is designed for intelligence gathering only and should not be used for any malicious purposes

## Advanced Features

### Framework Detection
The tool can detect common web frameworks and technologies used by the site, including:
- JavaScript frameworks (React, Angular, Vue.js, jQuery)
- Server-side frameworks (Django, Laravel, WordPress, etc.)
- Security technologies (Cloudflare, etc.)

### Security Analysis
HiddenOSINT analyzes security headers and provides recommendations, checking for:
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy

### Subpage Scanning
With the `--subpages` option, the tool can explore internal links to gather more comprehensive information about the target site.

### Report Generation
The HTML report provides a well-formatted, easy-to-read presentation of all collected data, with color-coded indicators for security issues and important findings.
