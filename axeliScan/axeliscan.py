import socket
import argparse
import cmd2
import subprocess

class PortScannerCLI(cmd2.Cmd):
    def __init__(self):
        super().__init__()
        self.intro = """
     

                   Welcome to Axeliscan

                  ____        _______ _      _____                       
    /\    \ \ / /  ____| |    |_   _|                      
   /  \    \ V /| |__  | |      | |    ___  ___ __ _ _ __  
  / /\ \    > < |  __| | |      | |   / __|/ __/ _` | '_ \ 
 / ____ \  / . \| |____| |____ _| |_  \__ \ (_| (_| | | | |
/_/    \_\/_/ \_\______|______|_____| |___/\___\__,_|_| |_|                                                        
                                                                                                           
               Simple Port Scanner by axeli
                                                    
    
        Type 'help' to see available commands"""
    
    def do_scan(self, line):
        """Scan ports on a target host: scan <host> <start_port> <end_port>"""
        args = line.split()
        if len(args) != 3:
            self.perror("Invalid arguments. Usage: scan <host> <start_port> <end_port>")
            return
        
        target_host = args[0]
        start_port = int(args[1])
        end_port = int(args[2])
        
        self.scan_ports(target_host, start_port, end_port)

    def scan_ports(self, target_host, start_port, end_port):
        print(f'Starting port scan on {target_host} from port {start_port} to {end_port}...\n')
        try:
            for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)  # Set timeout to 1 second

                try:
                    result = sock.connect_ex((target_host, port))
                    if result == 0:
                        service_name = socket.getservbyport(port)
                        print(f'Port {port}: Open ({service_name})')

                        # Attempt to receive data from the port to determine why it's open
                        banner = sock.recv(1024)  # Try to receive up to 1024 bytes from the port
                        if banner:
                            try:
                                # Attempt to decode received bytes using UTF-8
                                banner_str = banner.decode('utf-8').strip()
                                print(f'Received banner from {target_host}:{port}: {banner_str}')
                            except UnicodeDecodeError:
                                # If decoding as UTF-8 fails, print as hexadecimal representation
                                print(f'Received banner from {target_host}:{port}: {banner.hex()} (Hexadecimal)')
                        else:
                            print(f'No banner received from {target_host}:{port}')
                    else:
                        print(f'Port {port}: Closed')
                    sock.close()

                except KeyboardInterrupt:
                    print("\nExiting...")
                    break

                except socket.error:
                    print(f"Couldn't connect to port {port}")

        except socket.error as e:main()
        print(f"Socket error: {e}")

    def do_nmap(self, line):
        """Wrapper for nmap command"""
        try:
            output = subprocess.check_output(f"nmap {line}", shell=True, stderr=subprocess.STDOUT)
            print(output.decode().strip())
        except subprocess.CalledProcessError as e:
            print(f"Error executing nmap command: {e.output.decode().strip()}")
        except Exception as e:
            print(f"Error: {e}")

    def help_nmap(self):
        self.stdout.write("\nNmap Commands:\n")
        self.stdout.write("  nmap <target>\n")
        self.stdout.write("    Scan a single target host.\n")
        self.stdout.write("  nmap <target1> <target2> ...\n")
        self.stdout.write("    Scan multiple target hosts separated by spaces.\n")
        self.stdout.write("  nmap <start IP>-<end IP>\n")
        self.stdout.write("    Scan a range of IP addresses.\n")
        self.stdout.write("  nmap <target IP>/CIDR\n")
        self.stdout.write("    Scan a subnet (replace CIDR with subnet mask, e.g., /24).\n")
        self.stdout.write("  nmap -p <port1,port2,...> <target>\n")
        self.stdout.write("    Scan specific ports on the target host.\n")
        self.stdout.write("  nmap -p- <target>\n")
        self.stdout.write("    Scan all 65535main() ports on the target host.\n")
        self.stdout.write("  nmap -sV <target>\n")
        self.stdout.write("    Detect service versions on open ports.\n")
        self.stdout.write("  nmap -O <target>\n")
        self.stdout.write("    Attempt to identify the operating system of the target host.\n")
        self.stdout.write("  nmap -A <target>\n")
        self.stdout.write("    Enable aggressive scan with OS detection, version detection, script scanning, and traceroute.\n")
        self.stdout.write("  nmap -sU <target>\n")
        self.stdout.write("    Perform a UDP port scan.\n")
        self.stdout.write("  nmap -sS <target>\n")
        self.stdout.write("    Use TCP SYN packets for scanning (TCP SYN scan).\n")
        self.stdout.write("  nmap -sT <target>\n")
        self.stdout.write("    Perform a TCP connect scan.\n")
        self.stdout.write("  nmap -sP <target>\n")
        self.stdout.write("    Perform a ping scan to check which hosts are up.\n")
        self.stdout.write("  nmap -sR <target>\n")
        self.stdout.write("    Perform a remote OS detection using reverse DNS resolution.\n")
        self.stdout.write("  nmap -sI <zombie host> <target>\n")
        self.stdout.write("    Idle scan using an IP ID field from a zombie host.\n")
        self.stdout.write("  nmap -oN output.txt <target>\n")
        self.stdout.write("    Save scan results to a file in normal format.\n")
        self.stdout.write("  nmap -v <target>\n")
        self.stdout.write("    Enable verbose output to show more details during scanning.\n")

    def do_exit(self, line):
        """Exit the program"""
        return True

def main():
    cli = PortScannerCLI()
    cli.cmdloop()

if __name__ == "__main__":
    main()