import time
import hashlib
import base64
import hmac
import math 
import csv
import sys
import os
from multiprocessing.dummy import Pool as ThreadPool 

class Source:
    def __init__(self, secret, name):
        self.secret = secret
        self.name = name

def authCode(source):
    key = get_key(source.secret)
    message = math.floor(time.time() / 30)
    message_bytes = (message).to_bytes(len(str(message)), byteorder='big')
    hasher = hmac.new(key, message_bytes, hashlib.sha1)
    hashed = hasher.digest()
    offset = get_last_nibble(hashed)
    truncated_hash = hashed[offset:offset+4]
    code = calculate_code_from_truncated_hash(truncated_hash)
    padded_code = pad_code(code)
    source.code = padded_code
    print(source.name + ': ' + source.code)

# take the secret key to uppercase and then base32 decode the string
def get_key(secret):
    return base64.b32decode(secret.upper())

# convert a bytes object to its decimal representation
def bytes_to_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b)
    return result

# returns the last nibble of a bitstring
def get_last_nibble(hashed):
    return hashed[19] & 15

# ignore significant bits and modulo 1 million to ensure remainder is < 7 digits
def calculate_code_from_truncated_hash(truncated_hash):
    return ((bytes_to_int(truncated_hash) & 0x7fffffff) % 1000000)

# pad with zeros if remiander was < 6 digits
def pad_code(code):
    numAsString = str(code)
    while (len(numAsString) < 6):
        numAsString = "0" + numAsString
    return numAsString

def read_sources_from_file():
    list_of_sources = []
    data = open('mfa-data.csv')
    reader = csv.DictReader(data, delimiter=',')
    for row in reader:
        source = Source(row['secret'], row['name'])
        list_of_sources.append(source)

    return list_of_sources

def main():
    list_of_sources_to_authenticate = read_sources_from_file()
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            pool = ThreadPool(4)
            pool.map(authCode, list_of_sources_to_authenticate)
            pool.close()
            pool.join()
            remaining_seconds = math.floor(time.time()) % 30
            time.sleep(remaining_seconds)

    except KeyboardInterrupt:
        sys.exit()

main()