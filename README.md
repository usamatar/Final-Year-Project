# Vulnerability Assessment Tool 

## Overview
This project is a **Network & Web Vulnerability Scanner** built using **Django** and **Nmap** for scanning IP addresses, networks, and web applications for potential security vulnerabilities. It identifies issues like SQL injection, XSS, command injection, LFI, and RFI and provides security recommendations.

## Features
- **Web Vulnerability Scanning**: Detects SQL injection, XSS, command injection, Local File Inclusion (LFI), and Remote File Inclusion (RFI).
- **IP Address Scanning**: Uses `nmap` to retrieve OS information and potential vulnerabilities.
- **Network Scanning**: Checks for open ports, firewall misconfigurations, and insecure remote access.
- **Vulnerability Scanner**: Scans systems and applications for security weaknesses and provides mitigation recommendations.
- **Security Recommendations**: Provides guidance for securing web applications, operating systems, and networks.
- **Django API Endpoint**: Exposes scanning results via a RESTful API.

## Technologies Used
- **Python** (Django Framework)
- **Nmap** (Network scanning)
- **Requests** (For web scanning)
- **HTML, CSS, JavaScript** (Frontend templates)
- **SQLite/PostgreSQL** (Database for storing scan results)

## Installation
### Prerequisites
Ensure you have the following installed:
- Python 3.x
- Django
- Nmap (install using `sudo apt install nmap` on Linux/Mac or from [nmap.org](https://nmap.org/download.html))

### Steps to Install
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-scanner.git
   cd network-scanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run database migrations:
   ```bash
   python manage.py migrate
   ```
4. Start the Django server:
   ```bash
   python manage.py runserver
   ```
5. Open your browser and visit:
   ```
   http://127.0.0.1:8000/
   ```

## Usage
- Visit `/scan/` to scan a website.
- Visit `/scan_ip/` to scan an IP address.
- Visit `/network_ip/` to scan a network.
- Use `/vulnerability_scan/` to perform a full system vulnerability scan.
- API endpoint available at `/api/my-endpoint/`.

## Security Recommendations
### Web Security
- Sanitize user input to prevent SQL injection.
- Use **Content Security Policy (CSP)** to mitigate XSS attacks.
- Avoid executing user input as system commands.

### Operating System Security
- Apply security patches and updates regularly.
- Disable unnecessary services and ports.
- Implement **Multi-Factor Authentication (MFA)**.

### Network Security
- Keep **firewall configurations** updated.
- Regularly **audit remote access policies**.
- Use **VPNs** for secure remote connections.

## Contributing
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`
3. Commit your changes: `git commit -m "Added new feature"`
4. Push to the branch: `git push origin feature-branch`
5. Submit a Pull Request.

## License
This project is licensed under the **MIT License**.

## Contact
For any queries, feel free to reach out:
- **Email**: yourname@example.com
- **GitHub**: [yourusername](https://github.com/yourusername)

