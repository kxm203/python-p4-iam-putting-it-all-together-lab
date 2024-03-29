#!/usr/bin/env python3

from flask import request, session, jsonify, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.json
        required_fields = ['username', 'password', 'bio', 'image_url']

        if not all(field in data for field in required_fields):
            return make_response({'error': 'Missing required fields'}, 422)

        try:
            user = User(username=data['username'])
            user.password_hash = data['password']
            user.image_url = data.get('image_url')
            user.bio = data['bio']

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            response_data = {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }

            return response_data, 201
        except IntegrityError:
            db.session.rollback()
            return make_response({'error': "Username already exists"}, 422)
        except Exception as e:
            db.session.rollback()
            return make_response({'error': str(e)}, 500)

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id', None)
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
                return user_data, 200
            else:
                return {'error': 'User not found'}, 404
        else:
            return {'error': 'Unauthorized'}, 401
                

class Login(Resource):
    def post(self):
        try:
            request_json = request.get_json()
            username = request_json.get('username')
            password = request_json.get('password')
            
            if not (username and password):
                return make_response({'error': 'Missing username or password'}, 422)

            user = User.query.filter_by(username=username).first()
            if not user or not user.authenticate(password):
                return make_response({'error': 'Invalid username or password'}, 401)

            session['user_id'] = user.id
            return user.to_dict(), 200
        except KeyError as e:
            # Log the error for debugging
            app.logger.error(f'KeyError: {e}')
            return make_response({'error': 'Internal server error'}, 500)

class Logout(Resource):
    def delete(self):

        session['user_id'] = None

        return {}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)

        user = User.query.get(User, user_id)
        if not user:
            return make_response({'error': 'User not found'}, 404)

        return [recipe.to_dict() for recipe in user.recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return make_response({'error': 'Unauthorized'}, 401)

        data = request.json
        required_fields = ['title', 'instructions', 'minutes_to_complete']
        if not all(field in data for field in required_fields):
            return make_response({'error': 'Missing required fields'}, 422)

        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        except Exception as e:
            db.session.rollback()
            return make_response({'error': str(e)}, 500)

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)

   

