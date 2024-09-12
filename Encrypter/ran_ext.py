import random
import datetime

# Define ransomware types and their default extensions
ransomware_types = {
    "Conti": ".conti_crypt",
    "Ryuk": ".ryuk_encrypted",
    "REvil": ".revil_locked",
    "Maze": ".maze_secure"
}

# Function to generate a custom extension based on ransomware type
def generate_custom_extension(ransomware, include_timestamp=False, add_random_suffix=True):
    # Default extension based on ransomware type
    default_extension = ransomware_types.get(ransomware, ".generic_encrypted")
    
    # Add a timestamp if specified (optional)
    if include_timestamp:
        current_time = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        default_extension = f"{default_extension}_{current_time}"
    
    # Add a random suffix (optional) to make the extension more unique
    if add_random_suffix:
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        default_extension = f"{default_extension}_{random_suffix}"
    
    # Return the final customized extension
    return default_extension

# Example: User chooses Conti ransomware and wants a timestamp with a random suffix
user_selected_ransomware = "Ryuk"

# Generate the custom extension based on user input (without displaying full/partial in the name)
custom_extension = generate_custom_extension(user_selected_ransomware, include_timestamp=True, add_random_suffix=True)

# Output the result
print(f"Generated Extension: {custom_extension}")
