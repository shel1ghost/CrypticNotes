from flask import render_template, url_for, flash, redirect, request, session, make_response, jsonify
from app import app, db, bcrypt
from app.models import Users, Notes,  Keys
from app.utils.two_fa_email import send_otp_email, generate_otp
from app.utils.blowfish_encryption import generate_md5_key, encrypt_content_blowfish, decrypt_content_blowfish
from app.decorators import login_required
from datetime import datetime
import re
import os
import secrets
import json

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
@login_required
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
    return render_template('dashboard.html', logged_in=True, user_name=user_name)

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_name', None)
    #flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/create_new_note', methods=['GET', 'POST'])
@login_required
def create_new_note():
    user_name = session.get('user_name')
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        # Server-side validation for title and content
        if not title or len(title) > 100:
            flash('Title must be between 1 and 100 characters.', 'danger')
            return render_template('create_new_note.html', logged_in=True, user_name=user_name)
        if not content or len(content) < 10:
            flash('Content must be at least 10 characters long.', 'danger')
            return render_template('create_new_note.html', logged_in=True, user_name=user_name)
        
        # Generate MD5 key
        key_value = generate_md5_key()
        
         # Encrypt the title, content, and last modified date using Blowfish
        encrypted_title = encrypt_content_blowfish(title, key_value)
        encrypted_content = encrypt_content_blowfish(content, key_value)
        last_modified = datetime.utcnow().isoformat()
        encrypted_last_modified = encrypt_content_blowfish(last_modified, key_value)

        # Ensure the notes directory exists
        if not os.path.exists('notes'):
            os.makedirs('notes')
        
        # Save encrypted title, content, and last modified date to JSON file
        filename = f"{secrets.token_hex(8)}.json"
        filepath = os.path.join("notes", filename)
        with open(filepath, 'w') as file:
            json.dump({"title": encrypted_title, "content": encrypted_content, "last_modified": encrypted_last_modified}, file)
        
        # Save key to the database
        new_key = Keys(key_value=key_value)
        db.session.add(new_key)
        db.session.commit()

        # Save note information to the database
        new_note = Notes(user_id=session['user_id'], filename=filename, key_id=new_key.key_id)
        db.session.add(new_note)
        db.session.commit()
        
        flash('Note saved successfully!', 'success')
        return redirect(url_for('dashboard', logged_in=True, user_name=user_name))
    return render_template('create_new_note.html', logged_in=True, user_name=user_name)

@app.route('/view_notes')
@login_required
def view_notes():
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    notes = Notes.query.filter_by(user_id=user_id).all()
    decrypted_notes = []

    for note in notes:
        key = Keys.query.filter_by(key_id=note.key_id).first()
        with open(os.path.join("notes", note.filename), 'r') as file:
            data = json.load(file)
            decrypted_title = decrypt_content_blowfish(data['title'], key.key_value)
            decrypted_content = decrypt_content_blowfish(data['content'], key.key_value)
            decrypted_last_modified = decrypt_content_blowfish(data['last_modified'], key.key_value)
            dt_object = datetime.fromisoformat(decrypted_last_modified)
            formatted_date_time = dt_object.strftime("%H:%M %d/%m/%Y")
            decrypted_notes.append({
                "note_id": note.note_id,
                "title": decrypted_title,
                "content": decrypted_content,
                "last_modified": formatted_date_time
            })
    
    return render_template('view_notes.html', notes=decrypted_notes, logged_in=True, user_name=user_name)

@app.route('/settings')
@login_required
def settings():
    user_name = session.get('user_name')
    return render_template('settings.html', logged_in=True, user_name=user_name)

@app.route('/encryption_details')
@login_required
def encryption_details():
    user_name = session.get('user_name')
    return render_template('encryption_details.html', logged_in=True, user_name=user_name)

@app.route('/view_note')
@login_required
def view_note():
    user_name = session.get('user_name')
    note_id = request.args.get('note_id')
    if(note_id is None):
        return redirect('/view_notes')
    else:
        decrypted_note = {}
        note = Notes.query.filter_by(note_id=note_id).first()
        key = Keys.query.filter_by(key_id=note.key_id).first()
        with open(os.path.join("notes", note.filename), 'r') as file:
            data = json.load(file)
            decrypted_title = decrypt_content_blowfish(data['title'], key.key_value)
            decrypted_content = decrypt_content_blowfish(data['content'], key.key_value)
            decrypted_last_modified = decrypt_content_blowfish(data['last_modified'], key.key_value)

            dt_object = datetime.fromisoformat(decrypted_last_modified)
            formatted_date_time = dt_object.strftime("%H:%M %d/%m/%Y")
        
            decrypted_note['title'] = decrypted_title
            decrypted_note['content'] = decrypted_content
            decrypted_note['last_modified'] = formatted_date_time
        return render_template('view_note.html', note=decrypted_note, logged_in=True, user_name=user_name)


