import nmap

def scan_ip_address(ip_address):
    try:
        # Using nmap for OS vulnerability scanning
        nm = nmap.PortScanner()
        scan_data = nm.scan(ip_address, arguments='-O')
        os_info = scan_data['scan'][ip_address]['osclass'][0]['osfamily']
        return os_info
    except Exception as e:
        return str(e)