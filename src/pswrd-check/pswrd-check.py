import sys
import getopt
imports = ['hashlib', 'requests']

for i in imports:
    try:
        exec("import {module}".format(module=i))
    except ModuleNotFoundError as e:
        print(e)
        print("Install missing module to run this script")
        sys.exit()

API_url = "https://api.pwnedpasswords.com/range/"                          #more info on how it works https://haveibeenpwned.com/API/v3#PwnedPasswords
arguments = sys.argv[1:]
forbidden_symbols = ['<','>','(',')','[',']','/','\\','~','"','\'',' ',';']

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
    sys.exit()

try:
    modes, args = getopt.getopt(arguments, "p:w:h:")
except:
    mode_help()

def main():
    while True:
        try:
            pswrd = modes[0][1]
        except IndexError as e:
            print("Choose mode before typing password\n")
            mode_help()
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
                        mode_web(val)
                    elif name in ["-h", "--help"]:
                        mode_help()
                    else:
                        print("Unrecognized input try -h or --help for more info")

def mode_web(pswrd):
    while True:
        pswrd_hash = hashlib.sha1(pswrd.encode(), usedforsecurity=True)    #hashing password with sha1
        pswrd_hash_dig = pswrd_hash.hexdigest().upper()                    #extracting password digest first 5 letters
        pswrd_hash_dig_prefix = pswrd_hash_dig[:5]
        API_call = API_url + pswrd_hash_dig_prefix                         #haveibeenpwned verifies only 5 first letter of hashed password
        resp_url = requests.get(API_call)                                  #API response
        
        if ('200' in str(resp_url)):                                       #http response
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
    if pswrd:
        val = pswrd[0]
        wordlist_load(wordlist, val)
    for name, val in modes:
        if name in ["-p", "--password"]:
                wordlist_load(wordlist, val)
    print("Missing password argument")
    print("Try like this: -w <wordlist> -p <password>")

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
                mode_web(password)
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

def wordlist_load(wordlist, val):
    try:
        with open(wordlist, "r") as file:
            wordlist_split = (file.read().split(" "))
    except FileNotFoundError:
        print("Incorrect path to wordlist")
        sys.exit()
    for password in wordlist_split:
            if val == password:
                print("Password compromised")
                file.close()
                sys.exit()
    print("Password not found. You're good.")
    file.close()
    sys.exit()    

if __name__ == '__main__':
    if arguments:
        main()
    else:
        mode_picker()
