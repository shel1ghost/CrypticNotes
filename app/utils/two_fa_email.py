from flask_mail import Message
from app import mail
import secrets

def send_otp_email(user_email, otp):
    msg = Message('Your OTP Code', sender='cypticnotest123@gmail.com', recipients=[user_email])
    msg.body = f'Your OTP code is {otp}. Please enter this code to verify your device.'
    mail.send(msg)

def generate_otp():
    return secrets.choice(range(1000, 9999))
