import requests


def scan(domain):
    # Declare urls
    urls = []
    # URL dictionary path
    path = 'assets/directory.txt'
    # Open and read the file
    days_file = open(path, 'r')
    # Scan URLs
    while True:
        url = domain + days_file.readline().rstrip("\n")
        response = requests.get(url)
        if (response.status_code == 200 or
            response.status_code == 302 or
                response.status_code == 304):
            res = "[+] %s - status : HTTP %s: Found" % (url, response)
            urls.append(url)
        elif (response.status_code == 401):
            res = "[-] %s - status : HTTP %s: Unauthorized" % (url, response)
        elif (response.status_code == 403):
            res = "[-] %s - status : HTTP %s: Needs authorization" % (
                url, response)
        elif (response.status_code == 404):
            res = "[-] %s - status : HTTP %s: Not Found" % (url, response)
        elif (response.status_code == 405):
            res = "[-] %s - status: HTTP %s: Method Not Allowed" % (
                url, response)
        elif (response.status_code == 406):
            res = "[-] %s - status: HTTP %s: Not Acceptable" % (url, response)
        else:
            res = "[-] %s - status: HTTP %s: Unknown response" % (
                url, response)
        print(res)
    # Close the file
    days_file.close()
    return urls
