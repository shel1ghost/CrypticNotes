import hashlib
import random
import string

def generate_random_md5_with_number(number):
    # Generate a random string
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    # Generate MD5 hash
    md5_hash = hashlib.md5(random_str.encode()).hexdigest()
    # Append the number to the MD5 hash
    result = f"{md5_hash}{number}"
    return result

def extract_number_from_result(result):
    # Extract the number from the resulting string
    md5_length = 32  # Length of an MD5 hash in hexadecimal
    number = result[md5_length:]
    return number

