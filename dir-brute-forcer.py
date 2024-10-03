# A script to perform directory brute-forcing on a website to discover potentially hidden or unlinked files and directories.
import requests

def dir_brute_forcer(target_url, wordlist_file):
    with open(wordlist_file, 'r') as file:
        for line in file:
            dir_path = line.strip()
            full_path = f"{target_url}/{dir_path}"
            response = requests.get(full_path)
            if response.status_code == 200:
                print(f"Found: {full_path}")

target_url = "http://example.com"  # Target website
wordlist_file = "wordlist.txt"  # Path to wordlist file

dir_brute_forcer(target_url, wordlist_file)
