from flask import Flask, session, render_template, redirect, abort, url_for, flash, request
from itsdangerous import URLSafeTimedSerializer
import requests
import os
from datetime import datetime
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from forms import LoginForm, RegisterForm, ResetPasswordForm, EmailResetPasswordForm
from flask_migrate import Migrate
from funcs import main_page, send_confirmation_email, send_password_reset_email



app = Flask(__name__)
load_dotenv('.env')
app.config['SECRET_KEY'] = str(os.environ.get('SECRET_KEY'))
app.config['SECURITY_PASSWORD_SALT'] = str(os.environ.get('SECURITY_PASSWORD_SALT'))

### Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('POSTGRES_DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

### Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = str(os.environ.get('MAIL_USERNAME'))
app.config['MAIL_PASSWORD'] = str(os.environ.get('MAIL_PASSWORD'))
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

### DB Migration
migrate = Migrate(app, db)


### CSRF Protection
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email_confirmation_sent_on = db.Column(db.DateTime, nullable=True)
    email_confirmed = db.Column(db.Boolean, nullable=True, default=False)
    email_confirmed_on = db.Column(db.DateTime, nullable=True)
    favorites = relationship("Favorite", back_populates="owner")


class Favorite(db.Model):
    __tablename__ = "favorites"
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, nullable=False)
    recipe_name = db.Column(db.String(200), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    owner = relationship("User", back_populates="favorites")


class Rating(db.Model):
    __tablename__ = "ratings"
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, nullable=False)
    likes = db.Column(db.Boolean, nullable=False)
    dislikes = db.Column(db.Boolean, nullable=False)


# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_anonymous:
            return abort(403)
        elif current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.errorhandler(401)
def forbidden_access(e):
    return render_template('401.html'), 401


@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)


@app.route('/admin')
@admin_only
def admin():
    all_users = User.query.all()
    return render_template('admin.html', users=all_users[1:])


@app.route('/delete-user/<int:user_id>')
@admin_only
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('admin'))


def random_dish(dish_type):
    url = "https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/random"
    querystring = {"tags": f"{dish_type}", "number": "1"}
    headers = {
        'x-rapidapi-host': "spoonacular-recipe-food-nutrition-v1.p.rapidapi.com",
        'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
    }
    response = requests.request("GET", url, headers=headers,
                                params=querystring).json()
    recipe = response['recipes'][0]
    return main_page('index.html', current_user, Rating, recipe)


@app.route('/')
def home():
    url = "https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/random"
    headers = {
        'x-rapidapi-host': "spoonacular-recipe-food-nutrition-v1.p.rapidapi.com",
        'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
    }
    response = requests.get(url, headers=headers).json()
    recipe = response['recipes'][0]
    return main_page('index.html', current_user, Rating, recipe)


@app.route('/add-rating-like/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def add_rating_like(recipe_id):
    if request.method == 'POST':
        new_rating = Rating(
             recipe_id=recipe_id,
             likes=True,
             dislikes=False
        )
        db.session.add(new_rating)
        db.session.commit()
        return redirect(url_for('get_recipe', recipe_id=recipe_id))


@app.route('/add-rating-dislike/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def add_rating_dislike(recipe_id):
    if request.method == 'POST':
        new_rating = Rating(
            recipe_id=recipe_id,
            likes=False,
            dislikes=True
        )
        db.session.add(new_rating)
        db.session.commit()
        return redirect(url_for('get_recipe', recipe_id=recipe_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash("A user with that email already exists. Please login.")
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                name=form.name.data,
                email=form.email.data.lower(),
                password=hashed_password
            )
            send_confirmation_email(new_user.email, app, mail)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Thanks for registering!  Please check your email to confirm your email address.', 'success')
            return redirect(url_for('home'))
    return render_template("register.html", form=form)


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('The confirmation link is either invalid or has expired.', 'error')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user.email_confirmed:
        flash('Account already confirmed. Please login.', 'success')
        return redirect(url_for('login'))
    else:
        user.email_confirmed = True
        user.email_confirmed_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('Thank you for confirming your email address!')
        return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            elif not check_password_hash(user.password, form.password.data):
                flash('Incorrect info. Please try again.')
        elif not user:
            flash('User with that email does not exist, please register.')
            return redirect(url_for('register'))
    return render_template("login.html", form=form)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    form = EmailResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower().strip()).first()
        if user:
            send_password_reset_email(user.email, app, mail)
            flash('Confirmation email sent successfully, please check your email to reset password.')
            return redirect('login')
        elif not user:
            flash('User with that email does not exist, please check your information.', 'error')
            return redirect('reset')
    return render_template('reset.html', form=form)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = confirm_serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('The confirmation link is either invalid or has expired.', 'error')
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        new_password = generate_password_hash(
                form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
        if user.password == new_password:
            flash('You need to enter a password that is different from your previous password.', 'error')
            return redirect(url_for('reset_password', token=token))
        else:
            user.password = new_password
            db.session.add(user)
            db.session.commit()
            flash('Your password has been successfully reset. Please login with the new password.')
            return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, token=token)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/appetizer')
def appetizer():
    return random_dish('appetizer')


@app.route('/main')
def main():
    return random_dish('dinner')


@app.route('/dessert')
def dessert():
    return random_dish('dessert')


@app.route('/search/', methods=['GET', 'POST'])
def search_recipe():
    if request.method == 'POST':
        recipe_name = request.form.get('recipe-name')
        url = "https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/search"
        querystring = {"query": f"{recipe_name}", "number": "10"}
        headers = {
            'x-rapidapi-host': "spoonacular-recipe-food-nutrition-v1.p.rapidapi.com",
            'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
        }
        recipes = requests.get(url, params=querystring, headers=headers).json()['results']
        return render_template('recipes.html', recipes=recipes, current_user=current_user)


@app.route('/recipe/<int:recipe_id>')
def get_recipe(recipe_id):
    url = f"https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/{recipe_id}/information"
    headers = {
        'x-rapidapi-host': "spoonacular-recipe-food-nutrition-v1.p.rapidapi.com",
        'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
    }
    recipe = requests.get(url, headers=headers).json()
    return main_page('index.html', current_user, Rating, recipe)


@app.route('/add_favorite/<int:recipe_id>/<recipe_name>', methods=['GET', 'POST'])
@login_required
def add_favorite(recipe_id, recipe_name):
    if request.method == 'POST':
        if Favorite.query.filter_by(recipe_name=recipe_name).first():
            flash("This recipe is already in your favorites.")
            return redirect(url_for('favorites'))
        else:
            new_favorite = Favorite(
                recipe_name=recipe_name,
                recipe_id=recipe_id,
                owner=current_user
            )
            db.session.add(new_favorite)
            db.session.commit()
            return redirect(url_for('favorites'))


@app.route('/delete/<int:recipe_id>')
@login_required
def delete(recipe_id):
    recipe_to_delete = Favorite.query.get(recipe_id)
    db.session.delete(recipe_to_delete)
    db.session.commit()
    return redirect(url_for('favorites'))


@app.route('/favorites')
@login_required
def favorites():
    if current_user.is_authenticated:
        dishes = Favorite.query.filter_by(owner=current_user).all()
        return render_template("favorites.html", dishes=dishes)


if __name__ == '__main__':
    app.run(debug=True)
