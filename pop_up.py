import tkinter as tk
from email_retrieval import retrieve_unread_email_details, load_credentials
from rules import is_url_safe, is_valid_sender_domain
import pickle


class UnreadEmailsPopup:
    def __init__(self, email_retrieval_func, creds_func, valid_domains_file, api_key):
        self.root = tk.Tk()
        self.root.title("Unread Emails")
        self.email_retrieval_func = email_retrieval_func
        self.creds_func = creds_func
        self.valid_domains_file = valid_domains_file
        self.email_frames = {}
        self.api_key = api_key
        self.root.geometry("800x600")
        with open("voting_classifier.pkl", "rb") as file:
            self.voting_classifier = pickle.load(file)
        with open("vectorizer.pkl", "rb") as file:
            self.vectorizer = pickle.load(file)

    def update_emails(self):
        try:
            creds = self.creds_func()
            all_emails = self.email_retrieval_func(creds)

            current_ids = {email["id"] for email in all_emails}
            emails_to_remove = set(self.email_frames.keys()) - current_ids
            for email_id in emails_to_remove:
                self.email_frames[email_id].destroy()
                del self.email_frames[email_id]

            for email in all_emails:
                email_id = email["id"]
                sender_email = email["sender"]
                email_subject = email["subject"]
                message_body = email["body"]
                spf = self.extract_first_word(email.get("SPF", "N/A"))
                dkim = self.extract_first_word(email.get("DKIM", "N/A"))
                dmarc = self.extract_first_word(email.get("DMARC", "N/A"))

                spf_status = self.get_custom_status(spf)
                dkim_status = self.get_custom_status(dkim)
                dmarc_status = self.get_custom_status(dmarc)

                predicted_category = self.classify_email(message_body)

                if email_id in self.email_frames:
                    frame = self.email_frames[email_id]
                    self.update_email_labels(
                        frame,
                        sender_email,
                        email_subject,
                        predicted_category,
                        spf_status,
                        dkim_status,
                        dmarc_status,
                    )
                else:
                    frame = tk.Frame(self.root)
                    frame.grid(sticky="w")
                    self.create_email_labels(
                        frame,
                        sender_email,
                        email_subject,
                        predicted_category,
                        spf_status,
                        dkim_status,
                        dmarc_status,
                        email.get("urls", []),
                    )
                    self.email_frames[email_id] = frame
                    frame.grid_rowconfigure(7, minsize=10)
            # Schedule next update
            self.root.after(5000, self.update_emails)  # Update every 5 seconds

        except Exception as e:
            print(f"Error updating emails: {e}")

    def classify_email(self, message_body):
        processed_message = self.vectorizer.transform([message_body])
        prediction = self.voting_classifier.predict(processed_message)
        predicted_category = (
            "text looks like Phishing"
            if prediction == 1
            else " text looks like not Phishing"
        )
        return predicted_category

    def create_email_labels(
        self,
        frame,
        sender_email,
        email_subject,
        predicted_category,
        spf_status,
        dkim_status,
        dmarc_status,
        urls,
    ):
        sender_label = tk.Label(frame, text=f"From: {sender_email}", font=("Arial", 9))
        sender_label.grid(row=0, column=0, sticky="w")

        subject_label = tk.Label(
            frame, text=f"Subject: {email_subject}", font=("Arial", 9)
        )
        subject_label.grid(row=0, column=1, sticky="w")

        if predicted_category == "text looks like Phishing":
            category_label = tk.Label(
                frame,
                text=f"Category: {predicted_category}",
                fg="red",
                font=("Arial", 9),
            )
        else:
            category_label = tk.Label(
                frame,
                text=f"Category: {predicted_category}",
                fg="green",
                font=("Arial", 9),
            )

        category_label.grid(row=1, column=0, sticky="w")

        if spf_status == "Fail":
            spf_label = tk.Label(
                frame, text=f"SPF: {spf_status}", fg="red", font=("Arial", 9)
            )
            spf_label.grid(row=2, column=0, sticky="w")

        if dkim_status == "Fail":
            dkim_label = tk.Label(
                frame, text=f"DKIM: {dkim_status}", fg="red", font=("Arial", 9)
            )
            dkim_label.grid(row=3, column=0, sticky="w")

        if dmarc_status == "Fail":
            dmarc_label = tk.Label(
                frame, text=f"DMARC: {dmarc_status}", fg="red", font=("Arial", 9)
            )
            dmarc_label.grid(row=4, column=0, sticky="w")

        is_valid_domain = is_valid_sender_domain(sender_email, self.valid_domains_file)
        if not is_valid_domain:
            error_label = tk.Label(
                frame,
                text="The domain is not a valid or similar domain to any of the valid domains!",
                fg="red",
                font=("Arial", 9),
            )
            error_label.grid(row=5, column=0, columnspan=2, sticky="w")

        for index, url in enumerate(urls):
            is_safe = is_url_safe(url, self.api_key)
            if not is_safe:  # Display URL only if it's potentially unsafe
                result_label = tk.Label(
                    frame,
                    text=f"URL {index + 1}: {url} - Potentially Unsafe",
                    fg="red",
                    font=("Arial", 9),
                )
                result_label.grid(row=6 + index, column=0, sticky="w")

    def update_email_labels(
        self,
        frame,
        sender_email,
        email_subject,
        predicted_category,
        spf_status,
        dkim_status,
        dmarc_status,
    ):
        # Update sender and subject labels
        sender_label = frame.grid_slaves(row=0, column=0)[0]
        subject_label = frame.grid_slaves(row=0, column=1)[0]
        sender_label.config(text=f"From: {sender_email}")
        subject_label.config(text=f"Subject: {email_subject}")

        # Update category label
        category_label = frame.grid_slaves(row=1, column=0)[0]
        category_label.config(text=f"Category: {predicted_category}")

        # Update or create SPF label
        spf_label = frame.grid_slaves(row=2, column=0)
        if spf_status == "Fail":
            if not spf_label:
                spf_label = tk.Label(
                    frame, text=f"SPF: {spf_status}", fg="red", font=("Arial", 9)
                )
                spf_label.grid(row=2, column=0, sticky="w")
            else:
                spf_label[0].config(text=f"SPF: {spf_status}")
        elif spf_label:
            spf_label[0].destroy()

        # Update or create DKIM label
        dkim_label = frame.grid_slaves(row=3, column=0)
        if dkim_status == "Fail":
            if not dkim_label:
                dkim_label = tk.Label(
                    frame, text=f"DKIM: {dkim_status}", font=("Arial", 9)
                )
                dkim_label.grid(row=3, column=0, sticky="w")
            else:
                dkim_label[0].config(text=f"DKIM: {dkim_status}")
        elif dkim_label:
            dkim_label[0].destroy()

        # Update or create DMARC label
        dmarc_label = frame.grid_slaves(row=4, column=0)
        if dmarc_status == "Fail":
            if not dmarc_label:
                dmarc_label = tk.Label(
                    frame, text=f"DMARC: {dmarc_status}", font=("Arial", 9)
                )
                dmarc_label.grid(row=4, column=0, sticky="w")
            else:
                dmarc_label[0].config(text=f"DMARC: {dmarc_status}", font=("Arial", 9))
        elif dmarc_label:
            dmarc_label[0].destroy()

    def extract_first_word(self, text):
        if text == "N/A":
            return "N/A"
        return text.split()[0].lower()

    def get_custom_status(self, status):
        if status == "fail":
            return "Fail"

    def start(self):
        self.update_emails()
        self.root.mainloop()


if __name__ == "__main__":
    try:
        valid_domains_file = "emails.txt"
        api_key = "AIzaSyD3ad6krERgnO6ZXcUPiduqzO-rIgW2njE"
        popup = UnreadEmailsPopup(
            retrieve_unread_email_details, load_credentials, valid_domains_file, api_key
        )
        popup.start()

    except KeyboardInterrupt:
        print("Main thread stopped by user.")
