import requests
import hashlib
import sys

def get_api_response(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Fetching {res.status_code} as the response. Check the api and run again")
    return res

def get_pwned_count(hashes, hash_to_check):
   # creating a generator object to loop through
   hashes = (line.split(":") for line in hashes.text.splitlines())
   for h, count in hashes:
    if h == hash_to_check:
        return count 
   return 0
   
def pwned_api_check(password):
    hashed_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = hashed_password[:5], hashed_password[5:]
    response = get_api_response(first5_char)
    return get_pwned_count(response,tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"Whoops! It seems your password has been pwned {count} times. Time to change your password.")
        else:
            print("Your password is good to go!")
    return "Mission Accomplished!"

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))