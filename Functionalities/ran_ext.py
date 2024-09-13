import json
import random

# Load the ransomware JSON data from the file
def load_ransomware_data(json_file_path='ransom.json'):
    with open(json_file_path, 'r') as file:
        return json.load(file)

# Get the ransomware extension based on the selected ransomware
def get_ransomware_extension(ransomware_data, selected_ransomware_name):
    for ransomware in ransomware_data:
        if ransomware['ransomware'] == selected_ransomware_name:
            extension = ransomware.get('extension', f".{selected_ransomware_name.lower()}")
            return extension
    return None

# Function to simulate encryption and append the extension
def encrypt_file_with_extension(file_name, ransomware_name, file_extension):
    encrypted_file_name = f"{file_name}{file_extension}"
    print(f"File '{file_name}' encrypted by {ransomware_name}. New file: {encrypted_file_name}")
    return encrypted_file_name
