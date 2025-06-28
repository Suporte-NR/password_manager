import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
from functools import wraps
from itsdangerous import URLSafeTimedSerializer

# --- Configuração Inicial ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# --- Funções de Criptografia ---
def get_encryption_key(master_password):
    # Deriva uma chave da senha mestra. Não é ideal para produção, mas funciona para o projeto.
    key = base64.urlsafe_b64encode(master_password.encode('utf-8').ljust(32)[:32])
    return key

def get_cipher_suite(master_password):
    key = get_encryption_key(master_password)
    return Fernet(key)

# --- Modelos de Banco de Dados ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    credentials = db.relationship('Credential', backref='owner', lazy=True)

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(200), nullable=True)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(256), nullable=False)
    encrypted_notes = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False, default='Outros')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @property
    def password(self):
        master_password = session.get('master_password')
        if not master_password: raise Exception("Chave mestra não encontrada na sessão.")
        cipher_suite = get_cipher_suite(master_password)
        return cipher_suite.decrypt(self.encrypted_password.encode('utf-8')).decode('utf-8')

    @password.setter
    def password(self, plain_text_password):
        master_password = session.get('master_password')
        if not master_password: raise Exception("Chave mestra não encontrada na sessão.")
        cipher_suite = get_cipher_suite(master_password)
        self.encrypted_password = cipher_suite.encrypt(plain_text_password.encode('utf-8')).decode('utf-8')

    @property
    def notes(self):
        if not self.encrypted_notes: return ""
        master_password = session.get('master_password')
        if not master_password: raise Exception("Chave mestra não encontrada na sessão.")
        cipher_suite = get_cipher_suite(master_password)
        return cipher_suite.decrypt(self.encrypted_notes.encode('utf-8')).decode('utf-8')

    @notes.setter
    def notes(self, plain_text_notes):
        if not plain_text_notes:
            self.encrypted_notes = None
            return
        master_password = session.get('master_password')
        if not master_password: raise Exception("Chave mestra não encontrada na sessão.")
        cipher_suite = get_cipher_suite(master_password)
        self.encrypted_notes = cipher_suite.encrypt(plain_text_notes.encode('utf-8')).decode('utf-8')


# --- Decorador de Autenticação & Contexto ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_user():
    if 'user_id' in session:
        return dict(current_user=User.query.get(session['user_id']))
    return dict(current_user=None)

# --- Rotas ---
@app.route('/')
@login_required
def index():
    user_id = session['user_id']
    search_query = request.args.get('search_query', '')
    if search_query:
        search_term = f"%{search_query}%"
        credentials = Credential.query.filter(Credential.user_id == user_id, (Credential.service.ilike(search_term) | Credential.url.ilike(search_term) | Credential.username.ilike(search_term) | Credential.category.ilike(search_term))).all()
    else:
        credentials = Credential.query.filter_by(user_id=user_id).all()
    return render_template('index.html', credentials=credentials)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username, password = request.form['username'], request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Este nome de usuário já existe.', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registro bem-sucedido! Por favor, faça o login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, master_password = request.form['username'], request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, master_password):
            session['user_id'], session['master_password'] = user.id, master_password
            return redirect(url_for('index'))
        else:
            flash('Login falhou. Verifique o usuário e a senha.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user:
            token = serializer.dumps(user.id, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            flash(f'Usuário encontrado. Link de redefinição (simulado): {reset_url}', 'info')
        else: flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('forgot_password'))
    return render_template('request_reset.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try: user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('O link de redefinição é inválido ou expirou.', 'danger')
        return redirect(url_for('forgot_password'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.password_hash = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('Sua senha foi atualizada com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    if request.method == 'POST':
        new_credential = Credential(
            service=request.form['service'],
            url=request.form['url'],
            username=request.form['username'],
            category=request.form['category'],
            owner=User.query.get(session['user_id'])
        )
        new_credential.password = request.form['password']
        new_credential.notes = request.form.get('notes', '')
        db.session.add(new_credential)
        db.session.commit()
        flash('Senha adicionada com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('add_credential.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_credential(id):
    credential = Credential.query.get_or_404(id)
    if credential.user_id != session['user_id']:
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        credential.service = request.form['service']
        credential.url = request.form['url']
        credential.username = request.form['username']
        credential.category = request.form['category']
        credential.notes = request.form.get('notes', '')
        if request.form['password']:
            credential.password = request.form['password']
        db.session.commit()
        flash('Senha atualizada com sucesso!', 'success')
        return redirect(url_for('index'))
    return render_template('edit_credential.html', credential=credential)

@app.route('/delete/<int:id>')
@login_required
def delete_credential(id):
    credential_to_delete = Credential.query.get_or_404(id)
    if credential_to_delete.user_id != session['user_id']:
        flash('Acesso não autorizado.', 'danger')
        return redirect(url_for('index'))
    db.session.delete(credential_to_delete)
    db.session.commit()
    flash('Senha deletada com sucesso.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
