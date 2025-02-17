import os

class Config:
    SECRET_KEY = 'bb45b05b5d358f69e587e67565b66b83d8f215fee5135135'
    SQLALCHEMY_DATABASE_URI = 'postgresql://babi:root@localhost/crypticnotes'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

