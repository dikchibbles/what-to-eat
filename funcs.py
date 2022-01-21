import requests
from wordsegment import load, segment
from flask import render_template, url_for
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer


def main_page(template, cur_user, rating, recipe):
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
    all_likes = rating.query.filter_by(recipe_id=recipe_id, likes=True).count()
    all_dislikes = rating.query.filter_by(recipe_id=recipe_id, dislikes=True).count()
    return render_template(template,
                           dish_name=dish_name,
                           image=image,
                           instructions=instructions,
                           ingredients=ingredients,
                           category=category,
                           current_user=cur_user,
                           recipe_id=recipe_id,
                           likes=all_likes,
                           dislikes=all_dislikes)


def send_email(subject, user_email, html, app, mail):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], html=html, recipients=[user_email])
    mail.send(msg)


def send_confirmation_email(user_email, app, mail):
    """Sends a confirmation email with the unique token to the user."""
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    confirm_url = url_for(
        'confirm_email',
        token=confirm_serializer.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT']),
        _external=True)
    html = render_template('email_confirmation.html', confirm_url=confirm_url)
    send_email('Confirm Your Email Address', user_email, html, app, mail)


