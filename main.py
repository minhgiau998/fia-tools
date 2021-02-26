from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from validator_collection import validators, checkers
import network
import port
import whois
import google_dork
import spam_url
import sql_injection

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


class SqlInjectionIn(BaseModel):
    url: str

    class Config:
        schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com/artists.php?artist=1"
            }
        }


class SqlInjectionOut(BaseModel):
    is_vulnerable: bool

    class Config:
        schema_extra = {
            "example": {
                "is_vulnerable": True
            }
        }


@app.post("/network_scan", response_model=NetworkOut)
async def network_scan(network_in: NetworkIn):
    # Onlines Ip address
    onlines = network.scan(network_in.ip_address)
    # Response object
    network_out = NetworkOut(onlines=onlines)
    return network_out.dict()


@app.post("/port_scan", response_model=PortOut)
async def port_scan(port_in: PortIn):
    # Check validation
    if checkers.is_ip_address(port_in.ip_address) == False:
        raise HTTPException(status_code=422, detail="IP address is not valid")
    # Declare ports
    ports = port.scan(port_in.ip_address)
    # Response object
    network_out = NetworkOut(ports=ports)
    return network_out.dict()


@app.post("/whois_scan", response_model=WhoIsOut)
async def whois_scan(who_is_in: WhoIsIn):
    # Check url
    if checkers.is_domain(who_is_in.domain) == False:
        raise HTTPException(status_code=422, detail="Domain is not valid")
    # Declare domain
    response = whois.scan(who_is_in.domain)
    # Response object
    who_is_out = WhoIsOut(total_query=response['totalQuery'],
                          domain_name=response['domainName'],
                          registrar=response['registrar'],
                          registrant_name=response['registrantName'],
                          name_server=response['nameServer'],
                          status=response['status'],
                          creation_date=response['creationDate'],
                          expiration_date=response['expirationDate'])
    return who_is_out.dict()


@app.post("/google_dork_scan", response_model=GoogleDorkOut)
async def google_dork_scan(google_dork_in: GoogleDorkIn):
    # Search Google
    dorks = google_dork.scan(google_dork_in)
    # Response object
    google_dork_out = GoogleDorkOut(dorks=dorks)
    return google_dork_out


@app.post("/spam_url_checker", response_model=SpamUrlOut)
async def spam_url_checker(spam_url_in: SpamUrlIn):
    # Check validation
    if checkers.is_domain(spam_url_in.domain) == False:
        raise HTTPException(status_code=422, detail="Domain is not valid")
    # Check if url is spam or not
    is_spam = spam_url.check(spam_url_in.domain)
    # Response object
    spam_url_out = SpamUrlOut(is_spam=is_spam)
    return spam_url_out


@app.post("/sql_injection_scan", response_model=SqlInjectionOut)
async def sql_injection_scan(sql_injection_in: SqlInjectionIn):
    # Check validation
    if checkers.is_url(sql_injection_in.url) == False:
        raise HTTPException(status_code=422, detail="Url is not valid")
    # Check if url is vulnerable or not
    is_vulnerable = sql_injection.scan(sql_injection_in.url)
    # Response object
    sql_injection_out = SqlInjectionOut(is_vulnerable=is_vulnerable)
    return sql_injection_out
