from app import db
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os
import json

class Users(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    # Add more fields as needed

class Notes(db.Model):
    note_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    filename = db.Column(db.String(120), nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey('keys.key_id'), nullable=False)
    canvas_filename = db.Column(db.String(255), nullable=True)
    user = db.relationship('Users', backref=db.backref('notes', lazy=True))
    key = db.relationship('Keys', backref=db.backref('notes', cascade='all, delete-orphan', lazy=True))
    # Add more fields as needed

class Keys(db.Model):
    key_id = db.Column(db.Integer, primary_key=True)
    key_value = db.Column(db.String(32), nullable=False)
    # Add more fields as needed

