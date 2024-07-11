from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

#LOGIN CONFIG
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB


class User(db.Model,UserMixin):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    
    if request.method == "POST":
        #retrieve and hash PW
        input_pwd = request.form.get('password')
        hashed_pwd = generate_password_hash(input_pwd,method='pbkdf2:sha256',salt_length=8)
        db_email = request.form.get('email')
        if User.query.filter_by(email=db_email):
            flash("This email has already been registered. Log in instead.")
            return redirect(url_for("login"))
        #create new user and store
        new_user = User(
            email = request.form.get('email'),
            password = hashed_pwd,
            name = request.form.get('name')
        )
        db.session.add(new_user)
        db.session.commit()
        
        #logs in user
        login_user(new_user)
        
        return redirect(url_for("secrets"))
    else:
        return render_template("register.html")


@app.route('/login', methods= ["POST","GET"])
def login():
    if request.method == "POST":
        
        user = User.query.filter_by(email=request.form.get('email')).scalar()
        if not user:
            flash('This email is not registered. Please try again')
            return redirect(url_for("login"))
        
        if check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for("secrets")) 
        
        else:
            flash('Invalid password, please try again.')
            return redirect(url_for("login"))
            
        
    else:
        return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    user = db
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    print('tried downloading')
    return send_from_directory(
        'static',
        'files/cheat_sheet.pdf',
        as_attachment = True,
    )


if __name__ == "__main__":
    app.run(debug=True)
