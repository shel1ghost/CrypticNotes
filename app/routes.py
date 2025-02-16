from app import app
from flask import render_template

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/login')
def login():
    return render_template('login.html', login_page=True)

@app.route('/two_factor_auth')
def two_factor_auth():
    return render_template('two_factor_auth.html', two_factor_auth_page=True)