import smtplib
import os
from email.message import EmailMessage


def _send_email(to_email, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("SMTP_EMAIL")
    msg["To"] = to_email
    msg.set_content(body)

    server = smtplib.SMTP(os.getenv("SMTP_HOST"), int(os.getenv("SMTP_PORT")))
    server.starttls()
    server.login(
        os.getenv("SMTP_EMAIL"),
        os.getenv("SMTP_PASSWORD")
    )
    server.send_message(msg)
    server.quit()


def send_verification_otp(to_email, otp):
    _send_email(
        to_email=to_email,
        subject="TrustPoll - Verify your email",
        body=f"""
Hello,

Your TrustPoll verification code is:

{otp}

This code is valid for 10 minutes.
If you did not request this, please ignore this email.

 - TrustPoll Team
""",
    )


def send_registration_success_email(to_email):
    _send_email(
        to_email=to_email,
        subject="TrustPoll - Registration successful",
        body=f"""
Hello,

Your TrustPoll registration is complete.

You can now log in using:
- your VIT email
- your password

 - TrustPoll Team
""",
    )
