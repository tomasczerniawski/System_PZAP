from fuzzywuzzy import fuzz
import requests


def is_url_safe(url, api_key):
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    threat_info = {
        "client": {"clientId": "email-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatEntries": [{"url": url}],
            "platformTypes": ["ANY_PLATFORM"],
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        },
    }

    try:
        response = requests.post(endpoint, params={"key": api_key}, json=threat_info)
        response.raise_for_status()
        json_response = response.json()

        if "matches" in json_response:
            return False
        else:
            return True

    except requests.exceptions.RequestException as e:
        print(f"Error checking URL '{url}' safety: {e}")
        return False


def is_valid_sender_domain(sender_email, valid_domains_file):
    extracted_domain = extract_domain(sender_email)

    if extracted_domain:
        valid_domains = load_valid_domains(valid_domains_file)

        if is_valid_domain(extracted_domain, valid_domains):
            return True

    return False


def extract_domain(email):
    if "@" in email:
        _, domain = email.split("@", 1)
        return domain.lower()
    return None


def load_valid_domains(valid_domains_file):
    valid_domains = []
    with open(valid_domains_file, "r") as file:
        for line in file:
            domain = line.strip().lower()
            if domain:
                valid_domains.append(domain)
    return valid_domains


def is_valid_domain(input_domain, valid_domains):
    input_domain = input_domain.lower()

    for valid_domain in valid_domains:
        valid_domain = valid_domain.lower()

        similarity_ratio = fuzz.partial_ratio(valid_domain, input_domain)

        similarity_threshold = 99

        if similarity_ratio >= similarity_threshold:
            return True

    return False
