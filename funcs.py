import requests
from wordsegment import load, segment
from flask import render_template


def main_page(response, cur_user, rating):
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
    all_likes = rating.query.filter_by(recipe_id=recipe_id, likes=True).count()
    all_dislikes = rating.query.filter_by(recipe_id=recipe_id, dislikes=True).count()
    return render_template('index.html',
                           dish_name=dish_name,
                           image=image,
                           instructions=instructions,
                           ingredients=ingredients,
                           category=category,
                           current_user=cur_user,
                           recipe_id=recipe_id,
                           likes=all_likes,
                           dislikes=all_dislikes)
# def check_rating(recipe_id):
#     """
#     Finds all instances of the recipe_id in the DB
#     and counts how many there are in the DB.
#     """
#     all_likes = Rating.query.filter_by(recipe_id=recipe_id, likes=True).count()
#     all_dislikes = Rating.query.filter_by(recipe_id=recipe_id, dislikes=True).count()
#     return all_likes, all_dislikes


