import subprocess
import ipaddress


def scan(ip_address):
    # Declare onlines Ip address
    onlines = []
    # Create the network layer
    ip_net = ipaddress.ip_network(ip_address)
    # Get all the ip addresses in the network layer
    all_hosts = list(ip_net.hosts())
    # Customize child processes and command prompt
    info = subprocess.STARTUPINFO()
    info.dwFlags != subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = subprocess.SW_HIDE
    # Each ip address will ping that address
    for i in range(len(all_hosts)):
        output = subprocess.Popen(['ping', '-n', '1',
                                   '-w', '500', str(all_hosts[i])],
                                  stdout=subprocess.PIPE,
                                  startupinfo=info).communicate()[0]
        # If the unresponsive IP address is offline and vice versa.
        if "Destination host unreachable" in output.decode('utf-8'):
            print("[+] ", str(all_hosts[i]), "is Offline")
        elif "Request timed out" in output.decode('utf-8'):
            print("[+] ", str(all_hosts[i]), "is Offline")
        else:
            print("[+] ", str(all_hosts[i]), "is Online")
            onlines.append(str(all_hosts[i]))
    # Display online hosts
    print("-" * 5, " Host Live ", "-" * 5)
    for online in onlines:
        print("[+] ", online)
    return onlines
