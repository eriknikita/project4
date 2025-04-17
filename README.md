from socket import *
import optparse
from concurrent.futures import ThreadPoolExecutor
import sys
from typing import List, Optional

def scan_port(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return f'[+] {port}/tcp Open' if result == 0 else f'[-] {port}/tcp Closed'
    except Exception:
        return f'[-] {port}/tcp Error'

def port_scan(target_host: str, target_ports: List[int], max_workers: int = 50) -> None:
    try:
        target_ip = gethostbyname(target_host)
        print(f"\n[*] Scanning {target_host} ({target_ip})")
        print("[*] Starting scan...\n")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(scan_port, target_host, port)
                for port in target_ports
            ]
            for future in futures:
                print(future.result())

    except gaierror:
        print(f"\n[-] Error: Could not resolve hostname {target_host}")
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")

def validate_ports(ports_str: str) -> Optional[List[int]]:
    try:
        ports = []
        for port_item in ports_str.split(','):
            if '-' in port_item:
                start, end = map(int, port_item.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(port_item))
        return [p for p in ports if 1 <= p <= 65535]
    except:
        return None

def main():
    parser = optparse.OptionParser('''
Usage: %prog -H <target host> -p <target ports>
Example: %prog -H example.com -p 80,443,8080-8090
    '''.strip())
    
    parser.add_option('-H', dest='target_host', type='string', help='Target hostname or IP')
    parser.add_option('-p', dest='target_ports', type='string', help='Target port(s) (e.g., 80,443,8080-8090)')

    options, _ = parser.parse_args()

    if not options.target_host or not options.target_ports:
        parser.print_help()
        sys.exit(1)

    ports = validate_ports(options.target_ports)
    if not ports:
        print("[-] Error: Invalid port specification")
        sys.exit(1)

    port_scan(options.target_host, ports)

if __name__ == '__main__':
    main()
