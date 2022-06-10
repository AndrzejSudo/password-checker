from hmac import digest
import sys

try:
    import hashlib, requests
except ModuleNotFoundError as e:
    print(e + "\n"+"Install missing module to run this script")
    sys.exit()
finally:
    print("All modules imported")

API_url = "https://api.pwnedpasswords.com/range/"

def call_API(pswrd):
    pswrd_hash = hashlib.sha1(pswrd.encode(), usedforsecurity=True)    #hashing password with sha1
    pswrd_hash_dig = pswrd_hash.hexdigest().upper()[5:]                #extracting password digest first 5 letters for api
    API_call = API_url + pswrd_hash_dig                              #haveibeenpwned verifies only 5 first letter of hashed password
    resp_url = requests.get(API_call)                                       #API response
    
    if ('200' in str(resp_url)):                                            #http response: 200 - ok, 400 - not ok
        pswrd_cnt = 0
        resp_url_split = resp_url.text.splitlines()
        for hash in resp_url_split:
            hash_list = hash.split(':')
            for hash_line in hash_list:
                hash_split = hash_line[0]
                if str(pswrd_hash) in hash_split[5:]:
                    pswrd_cnt += 1
        resp_url_split = resp_url.text.splitlines()
        """
        for hash in resp_url_split:
            hash_rec = hash.split(':')[0]
            hash_cnt = hash.split(':')[1]
            if hash_rec == str(pswrd_hash)[5:]:
                    pswrd_cnt += int(hash_cnt)
        """
        """
        hashes = (line.split(':') for line in resp_url.text.splitlines())
        pswrd_cnt = next((int(pswrd_cnt) for t, pswrd_cnt in hashes if t == pswrd_hash_dig[5:]), 0)"""
        print(f"You password was compromised {pswrd_cnt} times")
        
    elif ('400' in str(resp_url)):
        print('Invalid input, try again')
        call_API(pswrd)

    else:
        print("No idea, try debugging")
        sys.exit()
    
call_API("password")
