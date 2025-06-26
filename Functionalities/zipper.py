import json
import os
import zipfile
import gzip
import py7zr  # Make sure to install this library using: pip install py7zr
import pyminizip  # Optional, only if you want to use encryption for ZIP files || Could have done it with cryptography module to 

# Function to zip files using zipfile and optional encryption
def zip_files(files, output_zip, password=None):
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file in files:
            zipf.write(file)
    if password:
        pyminizip.compress_multiple(files, [], output_zip, password, 5)

# Function to create a 7z archive
def create_7z_archive(files, output_7z):
    with py7zr.SevenZipFile(output_7z, 'w') as archive:
        for file in files:
            archive.write(file)

# Function to create a gzip archive
def create_gzip_archive(file, output_gz):
    with open(file, 'rb') as f_in:
        with gzip.open(output_gz, 'wb') as f_out:
            f_out.writelines(f_in)

# Load and extract JSON data
def load_json(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data

def create_archive_from_json(json_file, password=None):
    # Load the JSON data
    data = load_json(json_file)

    # Extract the zip_type (7zip, gzip, or zip)
    zip_type = data.get("zip_type")
    if not zip_type:
        print("Error: 'zip_type' not found in JSON")
        return

    # Collect target files mentioned in the JSON
    target_files = data.get("target", [])
    target_files = [file for file in target_files if os.path.exists(file)]

    if not target_files:
        print("No valid target files found.")
        return

    # Process based on zip_type
    if zip_type == "zip":
        output_file = "output.zip"
        zip_files(target_files, output_file, password)
        print(f"Created ZIP archive {output_file} successfully!")

    elif zip_type == "7zip":
        output_file = "output.7z"
        create_7z_archive(target_files, output_file)
        print(f"Created 7-Zip archive {output_file} successfully!")

    elif zip_type == "gzip":
        if len(target_files) != 1:
            print("gzip can only compress one file at a time.")
            return
        output_file = target_files[0] + ".gz"
        create_gzip_archive(target_files[0], output_file)
        print(f"Created gzip archive {output_file} successfully!")

    else:
        print(f"Unsupported zip type: {zip_type}")

if __name__ == "__main__":
    # Provide the path to your JSON file and password
    json_file = "data.json"  # Replace with your JSON file path
    password = "your_custom_password"  # Optional: Replace with your desired password (for ZIP encryption)

    create_archive_from_json(json_file, password)
