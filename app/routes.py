from flask import render_template, url_for, flash, redirect, request, session, make_response
from app import app, db, bcrypt
from app.models import Users
from app.utils.two_fa_email import send_otp_email, generate_otp
from app.decorators import login_required
import re

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not re.match(r'^[A-Za-z\s]{1,100}$', name):
            flash('Name should contain only letters and spaces, up to 100 characters.', 'danger')
        elif not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            flash('Invalid email address.', 'danger')
        elif not re.match(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).{8,}', password):
            flash('Password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.', 'danger')
        elif password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = Users(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
    user_logged_in = False
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = Users.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            session['user_name'] = user.name
            if request.cookies.get('remember_token') == 'true':
                #flash('Login successful! Welcome back.', 'success')
                return redirect(url_for('dashboard'))

            flash('Login successful! Please enter the OTP sent to your email.', 'success')
            
            otp = generate_otp()
            session['otp'] = otp
            send_otp_email(email, otp)
            
            return redirect(url_for('two_factor_auth'))
        else:
            flash('Login failed. Please check your email and password and try again.', 'danger')
    
    user_logged_in = 'user_id' in session
    return render_template('login.html', login_page=True)

@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if request.method == 'POST':
        otp_code = request.form.get('otp')
        remember = request.form.get('remember')
        
        if str(otp_code) == str(session.get('otp')):
            #flash('OTP verified successfully!', 'success')
            
            if remember:
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('remember_token', 'true', max_age=60*24*60*60)  # 60 days
                session.pop('otp', None)
                return response

            session.pop('otp', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    
    user_logged_in = 'user_id' in session
    return render_template('two_factor_auth.html', two_factor_auth_page=True)

@app.route('/dashboard')
@login_required
def dashboard():
    user_logged_in = 'user_id' in session
    user_name = session.get('user_name') 
    return render_template('dashboard.html', dashboard_page=True, user_name=user_name)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    #flash('You have been logged out.', 'success')
    return redirect(url_for('home'))