from ipaddress import ip_address
from django.shortcuts import render
from django.http import HttpResponse
import requests
from .ip_scanner import scan_ip_address
from scanner.utils import scan_network_ip, generate_network_recommendations
from django.http import JsonResponse
from .models import MyModel
from django.core.exceptions import ObjectDoesNotExist  # Import ObjectDoesNotExist for handling specific exceptions


def indexscan(request):
    return render(request, 'scanner/index.html')
def index(request):
    return render(request, 'index.html')

def about(request):
    return render(request, 'aboutus.html')

def compsysscan(request):
    return render(request, 'compsysscan.html')

def webscan(request):

    return render(request, 'webscan.html')

def contactus(request):
    return render(request, 'contactus.html')

def scanmain(request):
    return render(request, 'scan.html')

def networkscan(request):
    return render(request, 'networkscan.html')

def scan(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        if not url:
            return HttpResponse("Please enter a URL.")

        try:
            response = requests.get(url)
            host = response.url
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            
            # Checking for vulnerabilities
            sql_injection_vulnerable = check_sql_injection(url)
            xss_vulnerable = check_xss(url)
            command_injection_vulnerable = check_command_injection(url)
            lfi_vulnerable = check_lfi(url)
            rfi_vulnerable = check_rfi(url)
            

            # Recommendations
            web_recommendations = generate_web_recommendations()
            
        

        except requests.exceptions.RequestException as e:
            return HttpResponse(f"Error: {e}")

        context = {
            "host": host,
            "server": server,
            "powered_by": powered_by,
            "sql_injection_vulnerable": sql_injection_vulnerable,
            "xss_vulnerable": xss_vulnerable,
            "command_injection_vulnerable": command_injection_vulnerable,
            "lfi_vulnerable": lfi_vulnerable,
            "rfi_vulnerable": rfi_vulnerable,
            "web_recommendations": web_recommendations,
            
    
        }
        return render(request, 'scanner/result.html', context)

    return HttpResponse("Invalid request method. Please use POST.")

def scan_ip(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        if not ip_address:
            return HttpResponse("Please enter an IP address.")

        os_info = scan_ip_address(ip_address)

        context = {
            "ip_address": ip_address,
            "os_info": os_info,
            "os_command_injection_vulnerable": True,  # Example data
            "os_remote_code_execution_vulnerable": False,  # Example data
            "os_privilege_escalation_vulnerable": False,  # Example data
            "os_misconfigurations": "None",  # Example data
            "os_recommendations": generate_os_recommendations()
        }
        return render(request, 'scanner/result.html', context)

    return HttpResponse("Invalid request method. Please use POST.")
def scan_network_ip(ip_address):
    
    network_info = {
        "ip_address": ip_address,
        "network_computer_virus": False,
        "network_firewall_misconfigurations": True,
        "network_insecure_remote_access": False,
        "open_ports": [22, 80, 443],
        "services": {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS"
        }
    }
    return network_info

def network_ip(request):
    if request.method == 'POST':
        network_ip = request.POST.get('ip_address')
        if not ip_address:
            return HttpResponse("Please enter a IP address.")

        # Call the scan_network_ip function to get network scan results
        network_info = scan_network_ip(network_ip)

      
        context = {
            "network_info": network_info,
            "network_computer_virus": True, # Example data
            "network_firewall_misconfigurations": False, # Example data
            "network_insecure_remote_access": False, # Example data
            "network_misconfigurations": False, # Example data
            "network_recommendations": generate_network_recommendations,
        }
        return render(request, 'scanner/result.html', context)

    return HttpResponse("Invalid request method. Please use POST.")

def my_api_endpoint(request):
    try:
        data = list(MyModel.objects.all().values())  # Example: Retrieve all objects from MyModel
        return JsonResponse({'data': data})
    except ObjectDoesNotExist as e:
        return JsonResponse({'error': str(e)}, status=404)  # Handle specific exception (ObjectDoesNotExist)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)  # Catch-all for other exceptions

def check_sql_injection(url):
    payloads = ["' OR '1'='1'; -- ", "' OR '1'='1' /*"]
    for payload in payloads:
        vulnerable_url = url + payload
        try:
            response = requests.get(vulnerable_url)
            if "error in your SQL syntax" in response.text or "mysql_fetch_array()" in response.text:
                return True
        except:
            continue
    return False

def check_xss(url):
    payloads = ["<script>alert('XSS');</script>", "<img src=x onerror=alert('XSS');>"]
    for payload in payloads:
        try:
            response = requests.get(url, params={'q': payload})
            if payload in response.text:
                return True
        except:
            continue
    return False

def check_command_injection(url):
    payloads = ["; ls", "| ls"]
    for payload in payloads:
        vulnerable_url = url + payload
        try:
            response = requests.get(vulnerable_url)
            if "bin" in response.text or "root" in response.text:
                return True
        except:
            continue
    return False

def check_lfi(url):
    payloads = ["../../../../etc/passwd", "../../../../etc/hosts"]
    for payload in payloads:
        vulnerable_url = url + payload
        try:
            response = requests.get(vulnerable_url)
            if "root:x:" in response.text or "127.0.0.1" in response.text:
                return True
        except:
            continue
    return False

def check_rfi(url):
    payloads = ["http://test.com/shell.txt"]
    for payload in payloads:
        vulnerable_url = url + payload
        try:
            response = requests.get(vulnerable_url)
            if "shell" in response.text:
                return True
        except:
            continue
    return False


def check_network_computer_virus(network_info):
    if 'processes' in network_info:
        processes = network_info['processes']
        for process in processes:
            if 'virus' in process.lower():
                return True
    return False

def check_firewall_misconfigurations(network_info):
    if 'firewall' in network_info:
        firewall_settings = network_info['firewall']
        
        # Example logic to check for misconfigurations
        if 'status' in firewall_settings:
            status = firewall_settings['status']
            if status != 'enabled':
                return True
        
        # Add more specific checks as per your network_info structure
        
    return False

def check_insecure_remote_access(network_info):
    if 'remote_access' in network_info:
        remote_access_settings = network_info['remote_access']
        
        # Example logic to check for insecure remote access
        if 'authentication' in remote_access_settings:
            authentication_method = remote_access_settings['authentication']
            if authentication_method == 'none':
                return True
        
        # Add more specific checks as per your network_info structure
        
    return False

def check_weak_network_configurations(network_info):
    if 'network_configurations' in network_info:
        network_configurations = network_info['network_configurations']
        
        # Example logic to check for weak network configurations
        if 'password_strength' in network_configurations:
            password_strength = network_configurations['password_strength']
            if password_strength == 'weak':
                return True
        
        # Add more specific checks as per your network_info structure
        
    return False


def generate_web_recommendations():
    return [
        "Sanitize all user inputs to prevent SQL injection.",
        "Use Content Security Policy (CSP) to mitigate XSS.",
        "Avoid using user inputs directly in system commands.",
        "Use whitelisting to allow only specific files to be included.",
        "Disable allow_url_include in your PHP configuration.",

    ]
def generate_os_recommendations():
    return [
        "Apply the latest security patches and updates.",
        "Disable unnecessary services and ports.",
        "Use strong passwords and implement multi-factor authentication.",
        "Regularly audit user privileges and access controls.",
        "Implement intrusion detection and prevention systems (IDPS)."
    ]


def generate_network_recommendations():
    return [
        "Ensure all devices have updated antivirus software to prevent viruses.",
        "Regularly audit firewall settings to avoid misconfigurations.",
        "Implement secure VPNs and regularly review remote access policies.",
        "Maintain a patch management program to update all software regularly.",
        "Review and strengthen network segmentation and access controls."
    ]
