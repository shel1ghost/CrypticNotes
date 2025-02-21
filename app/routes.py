from flask import render_template, render_template_string, url_for, flash, redirect, request, session, make_response, jsonify, send_file
from app import app, db, bcrypt
from app.models import Users, Notes,  Keys
from app.utils.two_fa_email import send_otp_email, generate_otp
from app.utils.blowfish import blowfish_encrypt, blowfish_key_schedule, blowfish_round
from app.utils.blowfish_encryption import generate_md5_key, encrypt_content_blowfish, decrypt_content_blowfish
from app.decorators.decorators import login_required
from datetime import datetime
from app.utils.pdf_utils import generate_pdf, create_zip_file, cleanup_files
from app.utils.digital_signatures import sign_note_content, verify_note_content
from app.utils.generate_rsa_keys import generate_rsa_keys, serialize_private_key, serialize_public_key
import re
import os
import secrets
import json
import pytz
import uuid

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
            user = Users.query.filter_by(email=email).first()
            private_key, public_key = generate_rsa_keys(key_size=2048)
            private_key_pem = serialize_private_key(private_key)
            public_key_pem = serialize_public_key(public_key)
            with open(os.path.join(f"rsa_keys/public_key_{user.user_id}.pem"), "wb") as public_file:
                public_file.write(public_key_pem)
            with open(os.path.join(f"rsa_keys/private_key_{user.user_id}.pem"), "wb") as public_file:
                public_file.write(private_key_pem)
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
    user_id = session.get('user_id')
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
        timezone = pytz.timezone('Asia/Kathmandu')
        localized_time = datetime.now(timezone)
        last_modified = localized_time.isoformat()
        encrypted_last_modified = encrypt_content_blowfish(last_modified, key_value)

        private_key = os.path.join("rsa_keys", f"private_key_{user_id}.pem")
        signature = sign_note_content(title, content, private_key)

        # Ensure the notes directory exists
        if not os.path.exists('notes'):
            os.makedirs('notes')
        
        # Save encrypted title, content, and last modified date to JSON file
        filename = f"{secrets.token_hex(8)}.json"
        filepath = os.path.join("notes", filename)
        with open(filepath, 'w') as file:
            json.dump({"title": encrypted_title, "content": encrypted_content, "signature": signature, "last_modified": encrypted_last_modified}, file)
        
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
    if not notes:
        return render_template('view_notes.html', notes=False, logged_in=True, user_name=user_name)
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

@app.route('/view_note')
@login_required
def view_note():
    user_name = session.get('user_name')
    user_id = session.get('user_id')
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
            signature = data['signature']

            dt_object = datetime.fromisoformat(decrypted_last_modified)
            formatted_date_time = dt_object.strftime("%H:%M %d/%m/%Y")
        
            decrypted_note['title'] = decrypted_title
            decrypted_note['content'] = decrypted_content
            decrypted_note['last_modified'] = formatted_date_time
        
        public_key = os.path.join("rsa_keys", f"public_key_{user_id}.pem")
        valid_signature = verify_note_content(decrypted_note['title'], decrypted_note['content'], signature, public_key)
        if valid_signature:
            return render_template('view_note.html', note=decrypted_note, note_id=note_id, logged_in=True, user_name=user_name)
        else:
            flash('The integrity of this note seems to be compromised.', 'danger')
            return render_template('view_note.html', note=decrypted_note, note_id=note_id, logged_in=True, user_name=user_name)
        #return render_template('view_note.html', note=decrypted_note, note_id=note_id, logged_in=True, user_name=user_name)

@app.route('/edit_note', methods=['GET', 'POST'])
@login_required
def edit_note():
    user_name = session.get('user_name')
    user_id = session.get('user_id')
    note_id = request.args.get('note_id')

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
        
        note = Notes.query.filter_by(note_id=note_id).first()
        key = Keys.query.filter_by(key_id=note.key_id).first()
        
         # Encrypt the title, content, and last modified date using Blowfish
        encrypted_title = encrypt_content_blowfish(title, key.key_value)
        encrypted_content = encrypt_content_blowfish(content, key.key_value)
        timezone = pytz.timezone('Asia/Kathmandu')
        localized_time = datetime.now(timezone)
        last_modified = localized_time.isoformat()
        encrypted_last_modified = encrypt_content_blowfish(last_modified, key.key_value)

        private_key = os.path.join("rsa_keys", f"private_key_{user_id}.pem")
        signature = sign_note_content(title, content, private_key)

        filename = note.filename
        filepath = os.path.join("notes", filename)
        with open(filepath, 'w') as file:
            json.dump({"title": encrypted_title, "content": encrypted_content, "signature": signature, "last_modified": encrypted_last_modified}, file)
        
        flash('Note updated successfully!', 'success')
        return redirect(url_for('dashboard', logged_in=True, user_name=user_name))
        
    
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
        return render_template('edit_note.html', note=decrypted_note, note_id=note_id, logged_in=True, user_name=user_name)

@app.route('/delete_note')
@login_required
def delete_note():
    user_name = session.get('user_name')
    note_id = request.args.get('note_id')
    note = Notes.query.get_or_404(note_id)
    key_id = note.key_id
    
    # Delete the note file from the file system
    try:
        os.remove(os.path.join("notes", note.filename))
    except Exception as e:
        return redirect(url_for('view_notes'))
    
    # Delete the note from the database
    db.session.delete(note)
    db.session.commit()
    
    # Delete the associated key from the database
    key = Keys.query.get(key_id)
    if key:
        db.session.delete(key)
        db.session.commit()
    
    flash('Note deleted successfully!', 'success')
    return redirect(url_for('view_notes'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_name = session.get('user_name')
    if request.method == 'POST':
        user_id = session.get('user_id')
        user = Users.query.get_or_404(user_id)

        # Validate and update name
        new_name = request.form.get('name')
        if new_name:
            if not re.match(r'^[A-Za-z\s]{1,100}$', new_name):
                flash('Name should contain only letters and spaces, up to 100 characters.', 'danger')
                return redirect(url_for('user_settings'))
            if new_name != user.name:
                user.name = new_name
                session['user_name'] = new_name

        # Validate and update password
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        if old_password and new_password and confirm_new_password:
            if not bcrypt.check_password_hash(user.password, old_password):
                flash('Old password is incorrect.', 'danger')
                print(new_password)
                return render_template('settings.html', old_password=old_password, new_password=new_password, confirm_new_password=confirm_new_password)

            if new_password != confirm_new_password:
                flash('New passwords do not match.', 'danger')
                return render_template('settings.html', old_password=old_password, new_password=new_password, confirm_new_password=confirm_new_password)

            if not re.match(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).{8,}', new_password):
                flash('New password must be at least 8 characters long and include one uppercase letter, one lowercase letter, one number, and one special character.', 'danger')
                return render_template('settings.html', old_password=old_password, new_password=new_password, confirm_new_password=confirm_new_password)

            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        db.session.commit()
        flash('Your changes have been saved successfully.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('settings.html', logged_in=True, user_name=user_name)

@app.route('/encryption_details')
@login_required
def encryption_details():
    user_name = session.get('user_name')
    key = b"mysecretkey"
    subkeys = blowfish_key_schedule(key)

    plaintext = b"HelloBlow"
    plaintext_block = list(plaintext[:8])
    steps = {}
    text = plaintext.decode('utf-8')
    
    L = int.from_bytes(plaintext_block[:4], byteorder='big')
    R = int.from_bytes(plaintext_block[4:], byteorder='big')
    
    #steps.append(f"Initial L = {L:#010x}, R = {R:#010x}")
    steps["first_step"] = f"Initial L = {L:#010x}, R = {R:#010x}"
    
    for i in range(0, 16, 2):
        L, R = blowfish_round(L, R, subkeys[i:i+2], i // 2 + 1)
        L &= 0xFFFFFFFF
        R &= 0xFFFFFFFF
        #steps.append(f"Round {i // 2 + 1}: L = {L:#010x}, R = {R:#010x}")
        steps[i // 2 + 1] = f"Round {i // 2 + 1}: L = {L:#010x}, R = {R:#010x}"
    
    final_ciphertext = L.to_bytes(4, byteorder='big') + R.to_bytes(4, byteorder='big')
    final_hex = final_ciphertext.hex()
    
    #steps.append(f"Final L = {L:#010x}, R = {R:#010x}")
    #steps.append(f"Ciphertext (Hex): {final_hex}")
    steps["final_step"] = f"Final L = {L:#010x}, R = {R:#010x}"

    data = {
        'plaintext': text,
        'ciphertext': final_hex,
        'steps': steps,
        'subkeys': subkeys
    }

    return render_template('encryption_details.html', data=data, logged_in=True, user_name=user_name)

@app.route('/delete_account', methods=['GET', 'POST'])
@login_required
def delete_account():
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    user = Users.query.get_or_404(user_id)

    if request.method == 'POST':
        password = request.form.get('password')

        if not bcrypt.check_password_hash(user.password, password):
            flash('Password is incorrect.', 'danger')
            render_template('account_deletion.html', password=password, logged_in=True, user_name=user_name)
        else:
            # Delete all notes associated with the user
            notes = Notes.query.filter_by(user_id=user_id).all()
            for note in notes:
                # Delete the note file from the file system
                try:
                    os.remove(os.path.join("notes", note.filename))
                except Exception as e:
                    flash(f"An error occurred while trying to delete the note file: {str(e)}", 'danger')
                    render_template('account_deletion.html', logged_in=True, user_name=user_name)

                # Delete the associated key from the database
                key = Keys.query.get(note.key_id)
                if key:
                    db.session.delete(key)
        
                # Delete the note from the database
                db.session.delete(note)
        
            # Delete the user from the database
            db.session.delete(user)
            db.session.commit()

            # Clear the session and logout the user
            session.pop('user_id', None)
            session.pop('user_name', None)
            response = make_response("Cookie has been deleted")
            response.delete_cookie('remember_token')
            response.delete_cookie('otp')
            flash('Your account has been deleted successfully.', 'success')
            return redirect(url_for('login'))

    return render_template('account_deletion.html', logged_in=True, user_name=user_name)

@app.route('/search', methods=['POST'])
@login_required
def search_note():
    query = request.form['query'].lower()
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    notes = Notes.query.filter_by(user_id=user_id).all()
    if not notes:
        return render_template('view_notes.html', notes=False, logged_in=True, user_name=user_name)
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
    
    search_results = []
        
    for entry in decrypted_notes:
        if query in entry.get('title').lower():
            search_results.append(entry)
    
    response = '''
        {% for note in search_results %}
            <div class="note">
                <div class="note_headings">
                    <h2>{{ note.title }}</h2>
                    <p>{{ note.content[:100] }}...</p>
                    <p><small>Last modified: {{ note.last_modified }}</small></p>
                </div>
                <div class="note_buttons">
                    <button onclick="location.href='{{ url_for('view_note', note_id=note.note_id) }}'">View</button>
                    <button onclick="location.href='{{ url_for('edit_note', note_id=note.note_id) }}'">Edit</button>
                </div>
            </div>
        {% endfor %}'''

    return render_template_string(response, search_results=search_results)

@app.route('/export_notes')
@login_required
def export_notes():
    user_id = session.get('user_id')
    user_name = session.get('user_name')
    notes = Notes.query.filter_by(user_id=user_id).all()
    if not notes:
        return render_template('view_notes.html', notes=False, logged_in=True, user_name=user_name)
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

    # Automatically get the base path of the current file (app.py)
    base_path = os.path.dirname(os.path.abspath(__file__))

    # Create a temporary directory to store PDFs within the base path
    temp_dir = os.path.join(base_path, 'temp')
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    # Generate PDFs from data
    pdf_filenames = []
    for item in decrypted_notes:
        title = item.get('title', 'Untitled')
        content = item.get('content', 'No content')
        pdf_filename = os.path.join(temp_dir, f'{title}.pdf')
        generate_pdf(title, content, pdf_filename)
        pdf_filenames.append(pdf_filename)

    # Create a zip file containing all PDFs in the base path
    zip_filename = os.path.join(base_path, 'pdfs.zip')
    create_zip_file(pdf_filenames, zip_filename)

    # Send the zip file as a download
    response = send_file(zip_filename, as_attachment=True)

    # Cleanup temporary files
    cleanup_files(pdf_filenames)

    return response


@app.route('/view_shared_note')
@login_required
def view_shared_note():
    pass



