import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
!! DROPS ALL RECORDS AND STARTS THE DB FROM SCRATCH
!! MUST BE UNCOMMENTED ON FIRST RUN
'''
# db_drop_and_create_all()

## ROUTES

# An endpoint to handle GET requests for drinks.
@app.route('/drinks')
def get_drinks():
    drinks = Drink.query.all()
    formatted_drinks = [drink.short() for drink in drinks]

    return jsonify({
        'success': True,
        'drinks': formatted_drinks
    }), 200

# An endpoint to handle GET requests for drink details.
@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def get_drinks_detail(jwt):
    try:
        drinks = Drink.query.all()
        formatted_drinks = [drink.long() for drink in drinks]

        return jsonify({
            'success': True,
            'drinks': formatted_drinks
        }), 200
    except Exception:
        abort(422)

# An endpoint to POST a new drink
@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(jwt):
    body = request.get_json()

    title = body.get('title', None)
    recipe = body.get('recipe', None)

    try:
        drink = Drink(title=title, recipe=json.dumps(recipe))
        drink.insert()

        return jsonify({
            'success': True,
            'drinks': drink.long()
        }), 200
    except Exception:
        abort(422)

# An endpoint to PATCH a drink by id
@app.route('/drinks/<int:drink_id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def patch_drink(jwt, drink_id):
    body = request.get_json()

    try:
        drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

        if drink is None:
            abort(404)

        if 'title' in body:
            drink.title = body.get('title')

        drink.update()

        return jsonify({
            'success': True,
            'drinks': [drink.long()]
        }), 200
    except Exception:
        abort(400)

# An endpoint to DELETE a drink by id
@app.route('/drinks/<int:drink_id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(jwt, drink_id):
    try:
        drink = Drink.query.filter(Drink.id == drink_id).one_or_none()

        if drink is None:
            abort(404)

        drink.delete()

        return jsonify({
            'success': True,
            'deleted': drink_id
        })
    except Exception:
        abort(422)


## Error Handling

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'success': False,
        'error': 400,
        'message': 'bad request'
    }), 400


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 404,
        'message': 'resource not found'
    }), 404


@app.errorhandler(405)
def not_allowed(error):
    return jsonify({
        'success': False,
        'error': 405,
        'message': 'method not allowed'
    }), 405


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        'success': False,
        'error': 422,
        'message': 'unprocessable'
    }), 422


@app.errorhandler(500)
def server_error(error):
    return jsonify({
        'success': False,
        'error': 500,
        'message': 'internal server error'
    }), 500


@app.errorhandler(AuthError)
def handle_auth_error(error):
    return jsonify({
        'success': False,
        'error': error.status_code,
        'message': error.error
    }), error.status_code
