from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from sqlalchemy.exc import IntegrityError
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    serialize_rules = ('-_password_hash')

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship('Recipe', backref='user')

    @property 
    def password_hash(self):
        return self._password_hash
    
    @password_hash.setter
    def password_hash(self, password):
        byte_object = password.encode('utf-8')
        bcrypt_hash = bcrypt.generate_password_hash(byte_object)
        hash_object_as_string = bcrypt_hash.decode('utf-8')
        self._password_hash = hash_object_as_string

    def authenticate(self, password):
        return bcrypt.check_password_hash(
            self.password_hash, password.encode('utf-8'))
   
    def __repr__(self):
        return f'<User {self.username}, {self._password_hash}, {self.image_url}, {self.bio}>'



class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)

    # __table_arguments__ = (
    #     db.CheckConstraint('len(instructions) >= 50'),
    # )

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))



    @validates('instructions')
    def validates_instructions(self, key, instructions):
        if len(instructions) < 50:
           raise IntegrityError ("Instructions need to be greater than 50 characters.")
        return instructions


    def __repr__(self):
        return f'<{self.id}, {self.title}, {self.instructions}, {self.minutes_to_complete}, {self.user_id}'
