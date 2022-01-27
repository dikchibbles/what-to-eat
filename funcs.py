import requests
from wordsegment import load, segment
from flask import render_template, url_for
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer


def main_page(template, cur_user, rating, recipe, api_key):
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
    video_id = find_youtube_video_id(api_key, dish_name)
    return render_template(template,
                           dish_name=dish_name,
                           image=image,
                           instructions=instructions,
                           ingredients=ingredients,
                           category=category,
                           current_user=cur_user,
                           recipe_id=recipe_id,
                           likes=all_likes,
                           dislikes=all_dislikes,
                           video_id=video_id)


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


def send_password_reset_email(user_email, app, mail):
    """Sends an email with a password reset token."""
    confirm_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    reset_url = url_for(
        'reset_password',
        token=confirm_serializer.dumps(user_email, salt=app.config['SECURITY_PASSWORD_SALT']),
        _external=True)
    html = render_template('email_reset_password.html', reset_url=reset_url)
    send_email('Password Reset', user_email, html, app, mail)


def find_youtube_video_id(key, dish):
    url = "https://youtube.googleapis.com/youtube/v3/search"
    params = {
        'part': 'id',
        'regionCode': 'US',
        'q': dish,
        'key': key,
    }
    response = requests.get(url, params=params).json()
    video_id = response['items'][0]['id']['videoId']
    return video_id


