from hmac import digest
import sys

try:
    import hashlib, requests
except ModuleNotFoundError as e:
    print(e + "\n"+"Install missing module to run this script")
    sys.exit()
finally:
    print("All modules imported")

API-url = "https://api.pwnedpasswords.com/range/"

def call_API(pswrd):
    pswrd-hash = hashlib.sha1(b"{}".format(pswrd), usedforsecurity=True)    #hashing password with sha1
    pswrd-hash-dig = pswrd-hash.hexdigest().upper()                         #extracting password digest
    pswrd-hash-dig-prefix = pswrd-hash-dig[:5]                              #slicing diges prefix as an input for API
    API-call = API-url + pswrd-hash-dig-prefix
    req-url = requests.get(API-call)