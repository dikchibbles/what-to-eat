from flask import Flask, session, render_template, redirect, abort, url_for, flash, request
import requests
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect
from wordsegment import load, segment
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from forms import LoginForm, RegisterForm


app = Flask(__name__)
app.config['SECRET_KEY'] = 'sajfipnzxp994358hkjsadnfal'

### Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
    favorites = relationship("Favorite", back_populates="owner")


class Favorite(db.Model):
    __tablename__ = 'favorites'
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, nullable=False)
    recipe_name = db.Column(db.String(200), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    owner = relationship("User", back_populates="favorites")


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
    category = ''
    for key in list(recipe)[:8]:
        if recipe[key]:
            load()
            category_list = segment(key)
            category = ' '.join(category_list).lower()
            break
    dish_name = recipe['title']
    try:
        image = recipe['image']
    except KeyError:
        url = "https://bing-image-search1.p.rapidapi.com/images/search"
        querystring = {"q": f"{dish_name}"}
        headers = {
            'x-rapidapi-host': "bing-image-search1.p.rapidapi.com",
            'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
        }
        response = requests.request("GET", url, headers=headers,
                                    params=querystring).json()
        image = response['value'][0]['thumbnailUrl']
    instructions = recipe['instructions']
    ingredients = [ingredient['original'] for ingredient in recipe['extendedIngredients']]
    recipe_id = recipe['id']
    return render_template('index.html',
                           dish_name=dish_name,
                           image=image,
                           instructions=instructions,
                           ingredients=ingredients,
                           category=category,
                           current_user=current_user,
                           recipe_id=recipe_id)


@app.route('/')
def home():
    url = "https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/random"
    headers = {
        'x-rapidapi-host': "spoonacular-recipe-food-nutrition-v1.p.rapidapi.com",
        'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
    }
    response = requests.get(url, headers=headers).json()
    recipe = response['recipes'][0]
    category = ''
    for key in list(recipe)[:8]:
        if recipe[key]:
            load()
            category_list = segment(key)
            category = ' '.join(category_list).lower()
            break
    dish_name = recipe['title']
    try:
        image = recipe['image']
    except KeyError:
        url = "https://bing-image-search1.p.rapidapi.com/images/search"
        querystring = {"q": f"{dish_name}"}
        headers = {
            'x-rapidapi-host': "bing-image-search1.p.rapidapi.com",
            'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
        }
        response = requests.request("GET", url, headers=headers,
                                    params=querystring).json()
        image = response['value'][0]['thumbnailUrl']
    instructions = recipe['instructions']
    ingredients = []
    for ingredient in recipe['extendedIngredients']:
        ingredients.append(ingredient['original'])
    recipe_id = recipe['id']
    return render_template('index.html',
                           dish_name=dish_name,
                           image=image,
                           instructions=instructions,
                           ingredients=ingredients,
                           category=category,
                           current_user=current_user,
                           recipe_id=recipe_id)


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
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
    return render_template("register.html", form=form)


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


@app.route('/recipe/<int:recipe_id>')
@login_required
def get_recipe(recipe_id):
    url = f"https://spoonacular-recipe-food-nutrition-v1.p.rapidapi.com/recipes/{recipe_id}/information"
    headers = {
        'x-rapidapi-host': "spoonacular-recipe-food-nutrition-v1.p.rapidapi.com",
        'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
    }
    recipe = requests.get(url, headers=headers).json()
    category = ''
    for key in list(recipe)[:8]:
        if recipe[key]:
            load()
            category_list = segment(key)
            category = ' '.join(category_list).lower()
            break
    dish_name = recipe['title']
    try:
        image = recipe['image']
    except KeyError:
        url = "https://bing-image-search1.p.rapidapi.com/images/search"
        querystring = {"q": f"{dish_name}"}
        headers = {
            'x-rapidapi-host': "bing-image-search1.p.rapidapi.com",
            'x-rapidapi-key': "4122f3483amsh58a4641df90e077p13dbeejsn7d92b5bcd947"
        }
        response = requests.request("GET", url, headers=headers,
                                    params=querystring).json()
        image = response['value'][0]['thumbnailUrl']
    instructions = recipe['instructions']
    ingredients = []
    for ingredient in recipe['extendedIngredients']:
        ingredients.append(ingredient['original'])
    return render_template('show_recipe.html',
                           dish_name=dish_name,
                           image=image,
                           instructions=instructions,
                           ingredients=ingredients,
                           category=category,
                           current_user=current_user)


@app.route('/add_favorite/<int:recipe_id>/<recipe_name>', methods=['GET', 'POST'])
@login_required
def add_favorite(recipe_id, recipe_name):
    if request.method == 'POST':
        if Favorite.query.filter_by(recipe_name=recipe_name).first():
            flash("This recipe is already in your favorites.")
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
