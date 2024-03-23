from flask import Flask, request,render_template, redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt

# Flask Setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' # Store data into database.db
db = SQLAlchemy(app)   # Allows SQLAlchemy to interact with flask
app.secret_key = 'secret_key'   # python -c 'import secrets; print(secrets.token_hex())' 
                                # Sets a secret key for the Flask application, which is used for securely 
                                # signing the session cookie

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    # Constructor
    def __init__(self, email, password, name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

# Database Initialization
with app.app_context():
    db.create_all() # the User table will be created


@app.route('/')
@app.route('/index.html')
def index():
    return render_template('index.html')


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/') # done to prevent the form from being submitted again if the user refreshes the page
    
    return render_template('register.html')


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password): # if user is not None and password matches
            session['email'] = user.email # application remembers that the user is logged in.
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid user')

    return render_template('login.html') # when the user first navigates to the login page and 
                                         # needs to see the login form to enter their credentials
    
    
@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            return render_template('dashboard.html', user=user)
        else:
            return redirect('/login')
            
    return redirect('/login')


@app.route('/logout')
def logout():
    if 'email' in session:
        session.pop('email', None) # if the key does not exist, None is returned instead
    return redirect('/login')


if __name__ == '__main__':
    app.run('0.0.0.0', port=80, debug=True)