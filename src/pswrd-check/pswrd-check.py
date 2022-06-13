from hmac import digest
import sys

try:
    import hashlib, requests
except ModuleNotFoundError as e:
    print(e + "\n"+"Install missing module to run this script")
    sys.exit()
finally:
    print("All modules imported")

API_url = "https://api.pwnedpasswords.com/range/"                          #more info on how it works https://haveibeenpwned.com/API/v3#PwnedPasswords

def main():
    forbidden_symbols = ['<','>','(',')','[',']','/','\\','~','"','\'',' ',';']
    while True:
        pswrd = input("Enter password to check: ")  
        for symbol in pswrd:
            if symbol in forbidden_symbols:
                print('Improper symbol used in password, try again')
                continue
            else:
                call_API(pswrd)

def call_API(pswrd):
    while True:
        pswrd_hash = hashlib.sha1(pswrd.encode(), usedforsecurity=True)    #hashing password with sha1
        pswrd_hash_dig = pswrd_hash.hexdigest().upper()                    #extracting password digest first 5 letters for api
        pswrd_hash_dig_prefix = pswrd_hash_dig[:5]
        API_call = API_url + pswrd_hash_dig_prefix                         #haveibeenpwned verifies only 5 first letter of hashed password
        resp_url = requests.get(API_call)                                  #API response
        
        if ('200' in str(resp_url)):                                       #http response: 200 - ok, 400 - not ok
            pswrd_cnt = 0
            resp_url_split = resp_url.text.splitlines()

            for hashes in resp_url_split:
                hash = hashes.split(':')
                if hash[0] == pswrd_hash_dig[5:]:
                    pswrd_cnt += int(hash[1])
            print(f"Your password was found {pswrd_cnt} times in leaked databases")
            while True:
                response = input("Do you want to try another password? [Y\\N]\n")
                if response.upper() == 'Y':
                    main()
                elif response.upper() == 'N':
                    print('Bye')
                    sys.exit()
                else:
                    print("Unrecognized input, try again")
                    continue
            
        elif ('400' in str(resp_url)):
            print('Invalid input, try again')
            break

        else:
            print("No idea, try debugging")
            sys.exit()

if __name__ == '__main__':
    main()
