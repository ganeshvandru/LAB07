#REFERENCES
#https://www.geeksforgeeks.org/html-login-form/
#https://www.w3schools.com/howto/howto_css_login_form.asp
#https://discuss.python.org/t/how-to-create-a-registration-user-login-with-hashing/35735
#USAGE OF AI TO UNDERSTAND SIGN_UP AND SIGN_IN FUNCTIONS AND HTML PAGES





from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        signup_first_name = request.form['first_name']  
        signup_last_name = request.form['last_name']
        signup_email = request.form['email']
        signup_password = request.form['password']
        signup_confirm_password = request.form['confirm_password']

        if signup_password != signup_confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('sign_up'))

        if User.query.filter_by(email=signup_email).first():
            flash('Email address already in use!', 'danger')
            return redirect(url_for('sign_up'))

        hashed_password = generate_password_hash(signup_password, method='pbkdf2:sha256')
        new_user = User(first_name=signup_first_name, last_name=signup_last_name, email=signup_email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return render_template('thankyou.html', first_name=signup_first_name)  

    return render_template('sign_up.html')

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        signin_email = request.form['email']  
        signin_password = request.form['password']

        user = User.query.filter_by(email=signin_email).first()
        if user and check_password_hash(user.password, signin_password):
            session['user_id'] = user.id
            return redirect(url_for('secret_page'))

        else:
            flash('Invalid credentials!', 'danger')
            return redirect(url_for('sign_in'))

    return render_template('sign_in.html')

@app.route('/secret_page')
def secret_page():
    if 'user_id' not in session:
        return redirect(url_for('sign_in'))
    return render_template('secret_page.html')

@app.route('/sign_out')
def sign_out():
    session.pop('user_id', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)




