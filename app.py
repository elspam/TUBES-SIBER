from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import sqlite3
from functools import wraps
# [TAMBAHAN] Library untuk sanitasi input (Mencegah XSS)
import bleach

# [TAMBAHAN] Library untuk hashing password (Mencegah Plaintext Password Storage)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# [TAMBAHAN] Secret Key wajib ada untuk keamanan session
app.secret_key = 'Minummulto_na_ko_ng_damdamin_ko'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f'<Student {self.name}>'

# [TAMBAHAN] Decorator untuk membatasi akses halaman hanya bagi user yang sudah login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
        
# [MODIFIKASI] Fungsi Login diperbarui dengan verifikasi Hash Password
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        conn = sqlite3.connect('instance/students.db')
        cursor = conn.cursor()
        
        # [KODE LAMA/RENTAN] Authentication Bypass & Plaintext Password
        # cursor.execute("SELECT id FROM admin WHERE username=? AND password=?", (username, password))
        
        # [PERBAIKAN] Ambil hash password berdasarkan username saja
        cursor.execute("SELECT password FROM admin WHERE username=?", (username,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        # [PERBAIKAN] Verifikasi password menggunakan check_password_hash (Secure Hashing)
        if user_data and check_password_hash(user_data[0], password):
            session['logged_in'] = True
            flash('Login berhasil')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/')
@login_required # [TAMBAHAN] Proteksi halaman
def index():
    # Mengambil data untuk ditampilkan
    students = db.session.execute(text('SELECT * FROM student')).fetchall()
    return render_template('index.html', students=students)

@app.route('/add', methods=['POST'])
@login_required # [TAMBAHAN] Proteksi halaman
def add_student():
    name = request.form.get('name')
    age = request.form.get('age')
    grade = request.form.get('grade')
    
    # [TAMBAHAN] Sanitasi input untuk menghindari XSS sebelum masuk database
    name = bleach.clean(name, tags=[], strip=True)
    grade = bleach.clean(grade, tags=[], strip=True)
    
    connection = sqlite3.connect('instance/students.db')
    cursor = connection.cursor()

    # [KODE LAMA/RENTAN] SQL Injection (Raw Query dengan f-string/concatenation)
    # query = f"INSERT INTO student (name, age, grade) VALUES ('{name}', {age}, '{grade}')"
    # cursor.execute(query)

    # [PERBAIKAN] Menggunakan Parameterized Query (Tanda tanya sebagai placeholder)
    query = "INSERT INTO student (name, age, grade) VALUES (?, ?, ?)"
    cursor.execute(query, (name, age, grade))
    
    connection.commit()
    connection.close()
    return redirect(url_for('index'))


@app.route('/delete/<string:id>') 
@login_required # [TAMBAHAN] Proteksi halaman
def delete_student(id):
    # [KODE LAMA/RENTAN] SQL Injection pada parameter ID
    # db.session.execute(text(f"DELETE FROM student WHERE id={id}")) 

    # [PERBAIKAN] Menggunakan Bind Parameterized Query (:id)
    db.session.execute(text("DELETE FROM student WHERE id=:id"), {'id': id})
    db.session.commit()
    return redirect(url_for('index'))

# [TAMBAHAN] Fitur Logout untuk menghapus session
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required # [TAMBAHAN] Proteksi halaman
def edit_student(id):
    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        grade = request.form['grade']

        # [TAMBAHAN] Sanitasi input untuk menghindari XSS saat update
        name = bleach.clean(name, tags=[], strip=True)
        grade = bleach.clean(grade, tags=[], strip=True)
        
        # [KODE LAMA/RENTAN] SQL Injection saat Update
        # db.session.execute(text(f"UPDATE student SET name='{name}', age={age}, grade='{grade}' WHERE id={id}"))

        # [PERBAIKAN] Menggunakan Bind Parameterized Query
        db.session.execute(text("UPDATE student SET name=:name, age=:age, grade=:grade WHERE id=:id"), {'name': name, 'age': age, 'grade': grade, 'id': id})
        db.session.commit()
        return redirect(url_for('index'))
    else:
        # [KODE LAMA/RENTAN] SQL Injection saat Select
        # student = db.session.execute(text(f"SELECT * FROM student WHERE id={id}")).fetchone()
        
        # [PERBAIKAN] Menggunakan Bind Parameterized Query
        student = db.session.execute(text("SELECT * FROM student WHERE id=:id"), {'id': id}).fetchone()
        return render_template('edit.html', student=student)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # [MODIFIKASI] Pastikan debug=False saat production, disini True untuk dev
    app.run(host='0.0.0.0', port=5000, debug=True)