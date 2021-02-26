import socket


def scan(ip_address):
    # Declare ports
    ports = []
    # will scan ports between 1 to 1025
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        # returns an error indicator
        result = s.connect_ex((ip_address, port))
        if result == 0:
            print("Port {} is open".format(port))
            ports.append(port)
        else:
            print("Port {} is closed".format(port))
        s.close()
