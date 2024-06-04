import re
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
import os.path

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def load_credentials():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
        creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds


def extract_urls_from_body(body):
    urls = re.findall(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        body,
    )
    return urls


def retrieve_email_details(message_id, creds):
    try:
        service = build("gmail", "v1", credentials=creds)
        message = (
            service.users()
            .messages()
            .get(userId="me", id=message_id, format="full")
            .execute()
        )

        email_details = {
            "id": message["id"],
            "subject": "",
            "sender": "",
            "body": "",
        }

        # Retrieve email headersddd
        headers = message["payload"]["headers"]
        for header in headers:
            if header["name"] == "From":
                email_details["sender"] = header["value"]
            elif header["name"] == "Subject":
                email_details["subject"] = header["value"]

        # Retrieve email body (snippet)
        email_details["body"] = message["snippet"]

        # Retrieve the full email with parts
        full_message = (
            service.users().messages().get(userId="me", id=message_id).execute()
        )

        if "parts" in full_message["payload"]:
            for part in full_message["payload"]["parts"]:
                if part["mimeType"] == "text/html":
                    body_data = part["body"]["data"]
                    if body_data:
                        decoded_body = base64.urlsafe_b64decode(body_data).decode(
                            "utf-8"
                        )
                        extracted_urls = extract_urls_from_body(decoded_body)
                        if extracted_urls:
                            email_details["urls"] = extracted_urls

        # Extract additional headers
        for header in headers:
            if header["name"] == "Received-SPF":
                email_details["SPF"] = header["value"]
            elif header["name"] == "DKIM-Signature":
                email_details["DKIM"] = header["value"]
            elif header["name"] == "Authentication-Results":
                auth_results = header["value"]
                if "spf=" in auth_results:
                    email_details["SPF"] = (
                        auth_results.split("spf=")[1].split(";")[0].strip()
                    )
                if "dkim=" in auth_results:
                    email_details["DKIM"] = (
                        auth_results.split("dkim=")[1].split(";")[0].strip()
                    )
                if "dmarc=" in auth_results:
                    email_details["DMARC"] = (
                        auth_results.split("dmarc=")[1].split(";")[0].strip()
                    )

        return email_details

    except HttpError as error:
        print(f"An error occurred: {error}")
        return None


def retrieve_unread_email_details(creds):
    unread_emails = []
    try:
        service = build("gmail", "v1", credentials=creds)
        results = (
            service.users()
            .messages()
            .list(userId="me", labelIds=["INBOX", "UNREAD"])
            .execute()
        )
        messages = results.get("messages", [])

        for message in messages:
            message_id = message["id"]
            email_details = retrieve_email_details(message_id, creds)
            if email_details:
                unread_emails.append(email_details)

    except HttpError as error:
        print(f"An error occurred: {error}")

    return unread_emails
