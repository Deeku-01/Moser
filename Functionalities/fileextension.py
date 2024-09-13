import json
import random

# Load the ransomware JSON data from the file
json_file_path = 'ransom.json'

# Function to load ransomware data
def load_ransomware_data(json_file_path):
    with open(json_file_path, 'r') as file:
        return json.load(file)

# Function to randomly select a ransomware and its extension from the JSON data
def get_random_ransomware_extension(ransomware_data):
    ransomware = random.choice(ransomware_data)
    ransomware_name = ransomware['ransomware']
    extension = ransomware.get('extension', f".{ransomware_name.lower()}")
    return ransomware_name, extension

# Function to simulate encryption and append the extension
def encrypt_file(file_name, ransomware_name, file_extension):
    # Simulate "encryption" by appending the ransomware extension to the file name
    encrypted_file_name = f"{file_name}{file_extension}"
    print(f"File '{file_name}' encrypted by {ransomware_name}. New file: {encrypted_file_name}")
    return encrypted_file_name

# Example usage
ransomware_data = load_ransomware_data(json_file_path)

# Get a random ransomware and its extension
ransomware_name, file_extension = get_random_ransomware_extension(ransomware_data)

# Simulate encrypting a file by appending the ransomware-specific extension
file_name = "example_document"
encrypted_file_name = encrypt_file(file_name, ransomware_name, file_extension)
