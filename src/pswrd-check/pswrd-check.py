import sys
import getopt

try:
    import hashlib, requests
except ModuleNotFoundError as e:
    print(e + "\n"+"Install missing module to run this script")
    sys.exit()
finally:
    print("")

API_url = "https://api.pwnedpasswords.com/range/"                          #more info on how it works https://haveibeenpwned.com/API/v3#PwnedPasswords
arguments = sys.argv[1:]
forbidden_symbols = ['<','>','(',')','[',']','/','\\','~','"','\'',' ',';']

try:
    modes, args = getopt.getopt(arguments, "h:p:w:", ["mode1=", "mode2=", "mode3="])
except:
    print("invalid argument")
    sys.exit()

def main():
    while True:
        pswrd = modes[0][1]
        for symbol in pswrd:
            if symbol in forbidden_symbols:
                print('Improper symbol used in password, try again')
                continue
            else:
                for name, val in modes:
                    if name in ["-w", "--wordlist"]:
                        mode_list(val)
                        sys.exit()
                    elif name in ["-p", "--password"]:
                        mode_API(val)
                    elif name in ["-h", "--help"]:
                        mode_help()
                    else:
                        print("Unrecognized input try -h or --help for more info")

def mode_API(pswrd):
    while True:
        pswrd_hash = hashlib.sha1(pswrd.encode(), usedforsecurity=True)    #hashing password with sha1
        pswrd_hash_dig = pswrd_hash.hexdigest().upper()                    #extracting password digest first 5 letters
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
            sys.exit()  
        elif ('400' in str(resp_url)):
            print('Invalid input, try again')
            break
        else:
            print("No idea, check if service is online")

def mode_list(wordlist, *pswrd):
    for name, val in modes:
        if name in ["-p", "--password"] or pswrd:
            with open(wordlist, "r") as file:
                passwords = (file.read().split(" "))
                for password in passwords:
                    if val == password or pswrd == password:
                        print("Password compromised")
                        file.close()
                        sys.exit()
                print("Password not found. You're good.")
                file.close()
                sys.exit()
    print("Missing password argument")
    print("Try like this: -w <wordlist> -p <password>")

def mode_help():
    print("""
    usage: pswrd-check.py [-h] [-w] [-p] <INPUT>
    Checks password against given wordlist or via haveibeenpwned api

    positional arguments:
        INPUT               -   either password or wordlist, mode dependend
    
    options:
        -h, --help          -   displays help info
        -w, --wordlist      -   wordlists mode, requires password list file to check typed password f.e -w <wordlist.txt> -p <password>
        -p, --password      -   default mode, checks password leaks via haveibeenpwned api
    """)

def mode_picker():
    while True:
        print("""
        1. For web password check mode
        2. For wordlist check mode
        """)
        mode = input()
        if mode.isdecimal():
            if int(mode) == 1:
                password = input("Enter password: ")
                mode_API(password)
            elif int(mode) == 2:
                wordlist = input("Enter wordlist filename: ")
                password = input("Enter password: ")
                mode_list(wordlist, password)
            else:
                print("Unrecognized input, try again")
                continue
        else:
            print("Use only numbers to choose mode '1' or '2'")
            continue

if __name__ == '__main__':
    if arguments:
        main()
    else:
        mode_picker()
