from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow, fields
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from functools import wraps

import jwt, os

# Prepare App - Init App
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# App Configuration
app.config['SECRET_KEY'] = 'gZW6dh7Ex_YlWwncgIQBf'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'sqlite.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

# Class User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, email, username, password):
        self.email = email
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User> %r' % self.name

# Class Session
class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)
    
    keyword = db.Column(db.String(128), unique=True, nullable=False)
    duration = db.Column(db.String(128), nullable=False)

    user = db.relationship(
        'User', backref=db.backref('session', lazy=True))

    def __init__(self,user_id, keyword, duration):
        self.user_id = user_id
        self.keyword = keyword
        self.duration = duration

    def __repr__(self):
        return '<Keyword> %r' % self.keyword
    
# Create Schemas
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'username', 'password')

class SessionSchema(ma.Schema):
    id = fields.fields.Integer()
    user = fields.fields.Nested(UserSchema(only=("id","username","email",)))
    keyword = fields.fields.String()
    duration = fields.fields.Integer()
    

# Init Schemas
user_schema = UserSchema()
users_schema = UserSchema(many=True)
session_schema = SessionSchema()
sessions_schema = SessionSchema(many=True)

# Routes
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Coult not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('Coult not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({
            'token': token.encode().decode('utf-8')
        })
    return make_response('Coult not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    emailFound = User.query.filter_by(email=data['email']).first()
    
    '''
        check input before exceture query
    '''
    
    if not 'password_confirmation' in data:
        return jsonify({
            'message':'password confirmation is not found'
        }),400
    
    if not data['password'] == data['password_confirmation']:
        return jsonify({
            'message':'password is match with password confirmation'
        }),400
        
    if emailFound:
        return jsonify({
            'message':'email is already registered, please use another email account'
        }),400
    
    hashed_password = generate_password_hash(data['password'], method='sha256')
    email = data['email']
    username = data['username']
    password = hashed_password

    new_user = User(email, username, password)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)

# Token Authenticated
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        data = None
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(
                id=data['user_id']).first()
            token_exp = data['exp']
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'err':str(e), 'data':data}), 401

        return f(current_user, token_exp, *args, **kwargs)

    return decorated

@app.route('/sessions', methods=['GET'])
@token_required
def list_session(current_user, token_exp):
    seslist = Session.query.order_by(Session.user_id, Session.keyword, Session.duration).all()
    user_data = User.query.filter_by(id=current_user.id).first()
    
    found_user = False
    
    for data in seslist:
        if data.user_id == current_user.id:
            found_user = True
            break
    
    if not found_user:
        return jsonify({'message':'Session List not Found for this user.'}),400
    
    return sessions_schema.jsonify(seslist),200

@app.route('/sessions/create', methods=['GET'])
@token_required
def create_session(current_user, token_exp):
    token = None
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']

    if not token:
        return jsonify({'message': 'Token is missing!'}), 401
    
    sessiondata = Session.query.filter_by(keyword=token, user_id=current_user.id).first()
    
    if sessiondata:
        return jsonify({'message': 'Token is not expired!'}), 401
    
    new_sessions = Session(current_user.id, token, int(token_exp - datetime.utcnow().timestamp()))
    db.session.add(new_sessions)
    db.session.commit()

    return jsonify({'message':'OK'})

@app.route('/sessions/<session_id>', methods=['GET'])
@token_required
def get_session(current_user, token_exp, session_id):
    session = Session.query.filter_by(id=session_id, user_id=current_user.id).first()
    
    if session:
        return session_schema.jsonify(session)
    return jsonify({'message': 'Not Found!'})

@app.route('/sessions/update', methods=['GET'])
@token_required
def get_session_update(current_user, token_exp):
    token = None
    
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    
    session = Session.query.filter_by(keyword=token, user_id=current_user.id).first()
    
    session.duration = token_exp - datetime.utcnow().timestamp()
    db.session.commit()
    return jsonify({'message':'OK'})

@app.route('/sessions/delete', methods=['GET'])
@token_required
def get_session_delete(current_user, token_exp):
    token = None
    
    if 'x-access-token' in request.headers:
        token = request.headers['x-access-token']
    
    sessions = Session.query.filter_by(keyword=token, user_id=current_user.id).first()
    
    db.session.delete(sessions)
    db.session.commit()
    return jsonify({'message':'OK'})

@app.route('/', methods=["GET"])
def get():
   return jsonify({
     "ok": True,
     "msg": "REST API with FLASK"
   })

# Run server
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)