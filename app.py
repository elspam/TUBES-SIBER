from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import sqlite3
from functools import wraps
# untuk menghindari XSS
import bleach

app = Flask(__name__)
#Tambahkan app.secret.key untuk mengunci validasi session
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

#tambahkan validasi apakah user sudah login atau belum (decorator)
def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if not session.get('logged_in'):
			return redirect(url_for('login'))
		return f(*args, **kwargs)
	return decorated_function
		
#Fungsi login
@app.route('/login', methods=['GET','POST'])
def login():
	if request.method == 'POST':
		username = request.form.get('username')
		password = request.form.get('password')
		if username == "Rapid1945" and password == 'Ev3Rnight512*':
			session['logged_in'] = True
			session['username'] = username
			flash('Login berhasil')
			return redirect(url_for('index'))
		else:
			flash('username atau password salah')
	return render_template('login.html')

@app.route('/')
@login_required
def index():
    # RAW Query
    students = db.session.execute(text('SELECT * FROM student')).fetchall()
    return render_template('index.html', students=students)

@app.route('/add', methods=['POST'])
@login_required
def add_student():
    name = request.form.get('name')
    age = request.form.get('age')
    grade = request.form.get('grade')
    
    # Sanitasi input untuk menghindari XSS
    name = bleach.clean(name, tags=[], strip=True)
    grade = bleach.clean(grade, tags=[], strip=True)
    
    connection = sqlite3.connect('instance/students.db')
    cursor = connection.cursor()

    # RAW Query
    # db.session.execute(
    #     text("INSERT INTO student (name, age, grade) VALUES (:name, :age, :grade)"),
    #     {'name': name, 'age': age, 'grade': grade}
    # )
    # db.session.commit()
    #perbaikan menjadi parameterized query
    query = "INSERT INTO student (name, age, grade) VALUES (?, ?, ?)"
    cursor.execute(query, (name, age, grade))
    connection.commit()
    connection.close()
    return redirect(url_for('index'))


@app.route('/delete/<string:id>') 
@login_required
def delete_student(id):
    # RAW Query
    #perbaikan menjadi bind parameterized query
    db.session.execute(text("DELETE FROM student WHERE id=:id"), {'id': id})
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
	session.clear()
	return redirect(url_for('login'))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_student(id):
    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        grade = request.form['grade']

        # sanitasi input untuk menghindari XSS
        name = bleach.clean(name, tags=[], strip=True)
        grade = bleach.clean(grade, tags=[], strip=True)

        
        # RAW Query
        #perbaikan menjadi bind parameterized query
        db.session.execute(text("UPDATE student SET name=:name, age=:age, grade=:grade WHERE id=:id"), {'name': name, 'age': age, 'grade': grade, 'id': id})
        db.session.commit()
        return redirect(url_for('index'))
    else:
        # RAW Query
        #perbaikan menjadi bind parameterized query
        student = db.session.execute(text("SELECT * FROM student WHERE id=:id"), {'id': id}).fetchone()
        return render_template('edit.html', student=student)


# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)

