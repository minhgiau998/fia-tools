from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from validator_collection import validators, checkers
import subprocess
import ipaddress
import socket
import requests
import json
from googlesearch import search
from urllib.parse import urlparse
from spam_lists import SPAMHAUS_DBL

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
                "domain": "fpt.vn"
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

    class Config:
        schema_extra = {
            "example": {
                "total_query": "0",
                "domain_name": "fpt.vn",
                "registrar": "Công ty TNHH PA Việt Nam",
                "registrant_name": "Công ty Cổ phần Viễn thông FPT",
                "name_server": [
                    "dns-a.fpt.vn",
                    "dns-b.fpt.vn"
                ],
                "status": [
                    "clientTransferProhibited"
                ],
                "creation_date": "01-10-2000",
                "expiration_date": "10-06-2036"
            }
        }


class GoogleDorkIn(BaseModel):
    query: str
    lang: str
    number_of_results: int

    class Config:
        schema_extra = {
            "example": {
                "query": "FPT Information Assurance Club",
                "lang": "vi",
                "number_of_results": 10
            }
        }


class GoogleDorkOut(BaseModel):
    dorks: List[str]

    class Config:
        schema_extra = {
            "example": {
                "dorks": [
                    "https://www.facebook.com/fptinformationassurance",
                    "https://es-la.facebook.com/fptinformationassurance",
                    "https://uni.fpt.edu.vn/en-US/interesting-with-blockchain-and-the-launch-of-the-information-assurance-club",
                    "https://vymaps.com/VN/Fpt-Information-Assurance-Club-5569193/",
                    "https://fia.vercel.app/categories/hacking",
                    "https://fia.vercel.app/categories/penetration-testing",
                    "https://123job.vn/cv/goi-y-cach-viet-mau-cv-information-assurance-bang-tieng-anh-15944",
                    "https://vn.linkedin.com/in/thang-nq-0611",
                    "https://www.fis.com.vn/",
                    "http://www.toyo.ac.jp/uploaded/attachment/112036.pdf"
                ]
            }
        }


class SpamUrlIn(BaseModel):
    domain: str

    class Config:
        schema_extra = {
            "example": {
                "domain": "fia.vercel.app"
            }
        }


class SpamUrlOut(BaseModel):
    is_spam: bool

    class Config:
        schema_extra = {
            "example": {
                "is_spam": True
            }
        }


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


@app.post("/whois_scan", response_model=WhoIsOut)
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


@app.post("/google_dork", response_model=GoogleDorkOut)
async def google_dork(google_dork_in: GoogleDorkIn):
    # Search Google
    dorks = search(term=google_dork_in.query,
                   num_results=google_dork_in.number_of_results, lang=google_dork_in.lang)
    # Response object
    google_dork_out = GoogleDorkOut(dorks=dorks)
    return google_dork_out


@app.post("/spam_url_checker", response_model=SpamUrlOut)
async def spam_url_checker(spam_url_in: SpamUrlIn):
    # Check if url is spam or not
    is_spam = spam_url_in.domain in SPAMHAUS_DBL
    # Response object
    spam_url_out = SpamUrlOut(is_spam=not is_spam)
    return spam_url_out
