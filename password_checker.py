import requests
import hashlib
import sys


# Check if the password exists in the Have I Been Pwned API response
def pwned_api_check(password):
    # Convert the password into a SHA-1 hashed password
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Take the first 5 characters of the hashed password as the prefix
    first5_chars = sha1_password[:5]
    # Take the remaining characters of the hashed password as the suffix
    tail = sha1_password[5:]
    # Send a request to the Have I Been Pwned API to retrieve all hashed passwords with the same prefix
    response = request_api_data(first5_chars)
    # Check if the hashed password's suffix matches any of the retrieved hashed passwords
    return get_leakedpasswords_count(response, tail)


def get_leakedpasswords_count(hashes, hash_to_check):
    # Spiltting lines to get the hash and counter for each hashed password
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, counter in hashes:
        if h == hash_to_check:  # To match the actual password
            return int(counter)  # Password is leaked!
    return 0  # Password is safe, hasn't been leaked


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    try:
        response = requests.get(url)
        # Any other response like 400 or else - unauthorized
        if response.status_code != 200:
            raise RuntimeError(f'Error fetching: {response.status_code}, check the api and try again')
        return response
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f'Error fetching: {e}, check your network connection and try again')


def main(args):
    for password in args:
        counter = pwned_api_check(password)
        if counter:
            print(f'\033[1;31m{password}\033[0m has been leaked \033[1;35m{counter}\033[0m times! Please change it!')
        else:
            print(f'\033[1;31m{password}\033[0m has not been leaked. Therefore its \033[1;32msafe :)\033[0m')
    return 'All done!'


# User can type in as many password as he wants to check
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
    # pwned_api_check('CBDAR') # Checks if the API is working correctly by sending a string (password)
