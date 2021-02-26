import requests


def scan(domain):
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
    return json_data
