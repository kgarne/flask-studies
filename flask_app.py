from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
import pymysql

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('home.html')

class RegisterForm(Form):
    name = StringField('Username', [validators.Length(min=1, max=50)])
    phone = StringField('Phone', [validators.Length(min=10, max=11)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = RegisterForm(request.form)
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['name']
        password_candidate = request.form['password']

        # Create db connection
        conn = pymysql.connect(host='192.168.99.100', user='root', password='root', db='SchedulerPro', charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
        # Create cursor
        cur = conn.cursor()

        # Get user by username
        sql = "SELECT * FROM `users` WHERE `name`=%s"
        result = cur.execute(sql, ([username]))

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_candidate, password):
                app.logger.info('PASSWORD MATCHED')
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))

            else:
                error = 'Invalid login'
                return render_template('login.html', error=error, form=form)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error, form=form)

    return render_template('login.html', form=form)

# User Registration
@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        phone = form.phone.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create db connection
        conn = pymysql.connect(host='192.168.99.100', user='root', password='root', db='SchedulerPro', charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)

        # Create cursor
        a = conn.cursor()

        # Insert Record into users table
        sql = "INSERT INTO `users` (`name`, `phone`, `password`) VALUES(%s, %s, %s)"
        a.execute(sql, (name, phone, password))

        # Commit to DB
        conn.commit()

        # Close connection
        a.close()

        flash('You are now registered and can login', 'success')

        redirect(url_for('index'))
        return render_template('register.html', form=form)
    return render_template('register.html', form=form)
