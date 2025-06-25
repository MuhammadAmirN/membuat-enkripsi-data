from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from crypto_utils import generate_rsa_keys, encrypt_file_aes, decrypt_file_aes, encrypt_key_rsa, decrypt_key_rsa
from Crypto.PublicKey import RSA
import os

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'rahasia_sangat_aman'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/hybird_crypt'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 280,
    'pool_pre_ping': True
}
db = SQLAlchemy(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ====================== Model =======================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    rsa_public_key = db.Column(db.Text, nullable=False)
    rsa_private_key = db.Column(db.Text, nullable=False)

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    ciphertext = db.Column(db.LargeBinary)
    encrypted_key = db.Column(db.LargeBinary)
    nonce = db.Column(db.LargeBinary)
    tag = db.Column(db.LargeBinary)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    shared_with = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    encrypted_key_shared = db.Column(db.LargeBinary)

with app.app_context():
    db.create_all()

# ====================== Routes =======================

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='Username sudah terdaftar')

        private_key, public_key = generate_rsa_keys()
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            rsa_public_key=public_key.decode(),
            rsa_private_key=private_key.decode()
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Username atau password salah')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    users = User.query.all()
    my_files = File.query.filter_by(user_id=current_user.id).all()
    shared_files = File.query.filter_by(shared_with=current_user.id).all()
    all_files = File.query.all()

    return render_template(
        'upload.html',
        users=users,
        current_user=current_user,
        my_files=my_files,
        shared_files=shared_files,
        all_files=all_files
    )

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    file_data = file.read()
    filename = file.filename
    user = User.query.get(session['user_id'])

    aes_key, nonce, tag, ciphertext = encrypt_file_aes(file_data)
    encrypted_key = encrypt_key_rsa(aes_key, user.rsa_public_key.encode())

    shared_user_id = request.form.get('shared_with')
    encrypted_key_shared = None

    if shared_user_id == "ALL":
        shared_user_id = None
        encrypted_key_shared = encrypted_key
    elif shared_user_id and shared_user_id.isdigit():
        shared_user_id = int(shared_user_id)
        shared_user = User.query.get(shared_user_id)
        if shared_user:
            encrypted_key_shared = encrypt_key_rsa(aes_key, shared_user.rsa_public_key.encode())
    else:
        shared_user_id = None

    new_file = File(
        filename=filename,
        ciphertext=ciphertext,
        encrypted_key=encrypted_key,
        nonce=nonce,
        tag=tag,
        user_id=user.id,
        shared_with=shared_user_id,
        encrypted_key_shared=encrypted_key_shared
    )
    db.session.add(new_file)
    db.session.commit()

    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = File.query.get_or_404(file_id)
    current_user = User.query.get(session['user_id'])

    # Semua user download versi terenkripsi
    encrypted_path = os.path.join(UPLOAD_FOLDER, f"encrypted_{file.filename}")
    with open(encrypted_path, "wb") as f:
        f.write(file.ciphertext)
    return send_file(encrypted_path, as_attachment=True)

@app.route('/decrypt/<int:file_id>')
def decrypt_and_download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = File.query.get_or_404(file_id)
    current_user = User.query.get(session['user_id'])

    # Verifikasi hak akses
    if (
        current_user.id != file.user_id and
        not (file.shared_with is None and file.encrypted_key_shared) and
        current_user.id != file.shared_with
    ):
        return "❌ Anda tidak memiliki izin untuk mendekripsi file ini."

    try:
        if current_user.id == file.user_id:
            encrypted_key = file.encrypted_key
        else:
            encrypted_key = file.encrypted_key_shared

        private_key = RSA.import_key(current_user.rsa_private_key.encode())
        aes_key = decrypt_key_rsa(encrypted_key, private_key)
        decrypted = decrypt_file_aes(aes_key, file.nonce, file.tag, file.ciphertext)

        output_path = os.path.join(UPLOAD_FOLDER, f"decrypted_{file.filename}")
        with open(output_path, "wb") as f:
            f.write(decrypted)

        return send_file(output_path, as_attachment=True)

    except Exception as e:
        return f"❌ Gagal mendekripsi file: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)
