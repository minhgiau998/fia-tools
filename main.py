from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import subprocess
import ipaddress
import socket
import requests
import json
from validator_collection import validators, checkers

app = FastAPI()


class NetworkIn(BaseModel):
    ip_address: str

    class Config:
        schema_extra = {
            "example": {
                "ip_address": "192.168.1.0/24"
            }
        }


class NetworkOut(BaseModel):
    onlines: List[str]

    class Config:
        schema_extra = {
            "example": {
                "onlines": ["192.168.1.1", "192.168.1.2"]
            }
        }


class PortIn(BaseModel):
    ip_address: str

    class Config:
        schema_extra = {
            "example": {
                "ip_address": "192.168.1.1"
            }
        }


class PortOut(BaseModel):
    ports: List[str]

    class Config:
        schema_extra = {
            "example": {
                "ports": ["22", "443", "80"]
            }
        }


class WhoIsIn(BaseModel):
    domain: str

    class Config:
        schema_extra = {
            "example": {
                "domain": "www.abc.com"
            }
        }


class WhoIsOut(BaseModel):
    total_query: str
    domain_name: str
    registrar: str
    registrant_name: str
    name_server: List[str]
    status: List[str]
    creation_date: str
    expiration_date: str


@app.post("/network_scan", response_model=NetworkOut)
async def network_scan(network_in: NetworkIn):
    # Onlines Ip address
    onlines = []
    # Create the network layer
    try:
        ip_net = ipaddress.ip_network(network_in.ip_address)
    except ipaddress.AddressValueError(ValueError):
        raise HTTPException(
            status_code=422, detail="Network layer is not valid")
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
    # Response object
    network_out = NetworkOut(onlines=onlines)
    return network_out.dict()


@app.post("/port_scan", response_model=PortOut)
async def port_scan(port_in: PortIn):
    # Declare ports
    ports = []
    # Check validation
    if checkers.is_ip_address(port_in.ip_address) == False:
        raise HTTPException(status_code=422, detail="IP address is not valid")
    # will scan ports between 1 to 1025
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        # returns an error indicator
        result = s.connect_ex((port_in.ip_address, port))
        if result == 0:
            print("Port {} is open".format(port))
            ports.append(port)
        else:
            print("Port {} is closed".format(port))
        s.close()
    # Response object
    network_out = NetworkOut(ports=ports)
    return network_out.dict()


@app.post("/whois_scan")
async def whois_scan(who_is_in: WhoIsIn):
    # Declare domain
    domain = who_is_in.domain
    # Check url
    if checkers.is_domain(domain) == False:
        raise HTTPException(status_code=422, detail="Domain is not valid")
    # Send and receive results
    response = requests.get(
        "https://inet.vn/api/whois/" + domain)
    json_data = response.json()
    print(json.dumps(json_data))
    # Display results
    print("[+] Code: " + json_data['code'])
    print("[+] Total Query: " + str(json_data['totalQuery']))
    print("[+] Domain Name: " + json_data['domainName'])
    print("[+] Registrar: " + json_data['registrar'])
    print("[+] Registrant Name: " + json_data['registrantName'])
    print("[+] Name server:")
    for name_server in json_data['nameServer']:
        print(" [-] " + name_server)
    print("[+] Status:")
    for status in json_data['status']:
        print(" [-] " + status)
    print("[+] Creation Date: " + json_data['creationDate'])
    print("[+] Expiration Date: " + json_data['expirationDate'])
    # Response object
    who_is_out = WhoIsOut(total_query=json_data['totalQuery'],
                          domain_name=json_data['domainName'],
                          registrar=json_data['registrar'],
                          registrant_name=json_data['registrantName'],
                          name_server=json_data['nameServer'],
                          status=json_data['status'],
                          creation_date=json_data['creationDate'],
                          expiration_date=json_data['expirationDate'])
    return who_is_out.dict()
