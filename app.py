from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://" + os.environ.get("DATABASE_URL").partition("://")[2]

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
CORS(app)

# SQLAlchemy Tables
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False, unique=False)
    maps = db.relationship('Map', backref='user', lazy=True, cascade='all, delete, delete-orphan')
    tokens = db.relationship('Token', backref='user', lazy=True, cascade='all, delete, delete-orphan')
    sessions = db.relationship('Session', backref='user', lazy=True, cascade='all, delete, delete-orphan')
    
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

class Map(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=False)
    layout = db.Column(db.JSON, nullable=False, unique=False)
    pieces = db.Column(db.JSON, nullable=True, unique=False)
    image = db.Column(db.String, nullable=True, unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __init__(self, name, layout, pieces, image, user_id):
        self.name = name
        self.layout = layout
        self.pieces = pieces
        self.image = image
        self.user_id = user_id

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=False)
    stance = db.Column(db.String, nullable=False, unique=False)
    image = db.Column(db.String, nullable=False, unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __init__(self, name, stance, image, user_id):
        self.name = name
        self.stance = stance
        self.image = image
        self.user_id = user_id

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=False)
    data = db.Column(db.JSON, nullable=True, unique=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __init__(self, name, data, user_id):
        self.name = name
        self.data = data
        self.user_id = user_id

with app.app_context():
    db.create_all()


# Marshmallow Schemas
class SessionSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "data", "user_id")

session_schema = SessionSchema()
multiple_session_schema = SessionSchema(many=True)

class TokenSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "stance", "image", "user_id")

token_schema = TokenSchema()
multiple_token_schema = TokenSchema(many=True)

class MapSchema(ma.Schema):
    class Meta:
        fields = ("id", "layout", "name", "pieces", "image")

map_schema = MapSchema()
multiple_map_schema = MapSchema(many=True)

class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "username", "email", "maps", "tokens", "sessions")
    maps = ma.Nested(multiple_map_schema)
    tokens = ma.Nested(multiple_token_schema)
    sessions = ma.Nested(multiple_session_schema)

user_schema = UserSchema()
multiple_user_schema = UserSchema(many=True)


# Flask Endpoints
@app.route("/user/add", methods=["POST"])
def user_add():
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    username_taken_check = db.session.query(User).filter(User.username == username).first()
    if username_taken_check is not None:
        return jsonify({
            "status": 400,
            "message": "Username taken.",
            "data": {}
        })

    email_taken_check = db.session.query(User).filter(User.email == email).first()
    if email_taken_check is not None:
        return jsonify({
            "status": 400,
            "message": "Email already in use.",
            "data": {}
        })

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    record = User(username, email, hashed_password)
    db.session.add(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "User Added",
        "data": {
            "user": user_schema.dump(record)
        }
    })

@app.route("/user/login", methods=["POST"])
def login_user():
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    record = db.session.query(User).filter(User.email == email).first()
    if record is None:
        return jsonify({
            "status": 400,
            "message": "Invalid email or password",
            "data": {}
        })

    password_check = bcrypt.check_password_hash(record.password, password)
    if password_check is False:
        return jsonify({
            "status": 400,
            "message": "Invalid email or password",
            "data": {}
        })

    return jsonify({
        "status": 200,
        "message": "Valid email and password",
        "data": {
            "user": user_schema.dump(record)
        }
    })

@app.route("/user/get", methods=["GET"])
def user_get_all():
    records = db.session.query(User).all()
    return jsonify(multiple_user_schema.dump(records))

@app.route("/user/get/id/<id>", methods=["GET"])
def user_get_by_id(id):
    record = db.session.query(User).filter(User.id == id).first()
    return jsonify(user_schema.dump(record))

@app.route("/user/get/username/<username>", methods=["GET"])
def user_get_by_username(username):
    record = db.session.query(User).filter(User.username == username).first()
    return jsonify(user_schema.dump(record))


@app.route("/map/add", methods=["POST"])
def map_add():
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    name = data.get("name")
    layout = data.get("layout")
    pieces = data.get("pieces")
    image = data.get("image")
    user_id = data.get("user_id")

    count = 1
    finalName = name
    while db.session.query(Map).filter(Map.name == finalName).first() != None:
        count += 1
        finalName = f"{name} ({count})"

    record = Map(finalName, layout, pieces, image, user_id)
    db.session.add(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Map Added",
        "data": {
            "map": map_schema.dump(record)
        }
    })

@app.route("/map/update/<id>", methods=["PUT"])
def map_update(id):
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    name = data.get("name")
    pieces = data.get("pieces")
    image = data.get("image")

    record = db.session.query(Map).filter(Map.id == id).first()
    if name is not None:
        count = 1
        finalName = name
        while db.session.query(Map).filter(Map.name == finalName).first() != None:
            count += 1
            finalName = f"{name} ({count})"
        record.name = finalName
    if layout is not None:
        record.layout = layout
    if pieces is not None:
        record.pieces = pieces
    if image is not None:
        record.image = image

    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Map Updated",
        "data": {
            "map": map_schema.dump(record)
        }
    })

@app.route("/map/delete/<id>", methods=["DELETE"])
def map_delete(id):
    record = db.session.query(Map).filter(Map.id == id).first()
    db.session.delete(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Map Deleted",
        "data": {
            "map": map_schema.dump(record)
        }
    })


@app.route("/token/add", methods=["POST"])
def token_add():
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    name = data.get("name")
    stance = data.get("stance")
    image = data.get("image")
    user_id = data.get("user_id")

    count = 1
    finalName = name
    while db.session.query(Token).filter(Token.name == finalName).first() != None:
        count += 1
        finalName = f"{name} ({count})"

    record = Token(finalName, stance, image, user_id)
    db.session.add(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Token Added",
        "data": {
            "token": token_schema.dump(record)
        }
    })

@app.route("/token/update/<id>", methods=["PUT"])
def token_update(id):
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    name = data.get("name")
    image = data.get("image")

    record = db.session.query(Token).filter(Token.id == id).first()
    if name is not None:
        count = 1
        finalName = name
        while db.session.query(Token).filter(Token.name == finalName).first() != None:
            count += 1
            finalName = f"{name} ({count})"
        record.name = finalName
    if stance is not None:
        record.stance = stance
    if image is not None:
        record.image = image

    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Token Updated",
        "data": {
            "token": token_schema.dump(record)
        }
    })

@app.route("/token/delete/<id>", methods=["DELETE"])
def token_delete(id):
    record = db.session.query(Token).filter(Token.id == id).first()
    db.session.delete(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Token Deleted",
        "data": {
            "token": token_schema.dump(record)
        }
    })


@app.route("/session/add", methods=["POST"])
def session_add():
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    name = data.get("name")
    session_data = data.get("data")
    user_id = data.get("user_id")

    count = 1
    finalName = name
    while db.session.query(Session).filter(Session.name == finalName).first() != None:
        count += 1
        finalName = f"{name} ({count})"

    record = Session(finalName, session_data, user_id)
    db.session.add(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Session Added",
        "data": {
            "session": session_schema.dump(record)
        }
    })

@app.route("/session/update/<id>", methods=["PUT"])
def session_update(id):
    if request.content_type != "application/json":
        return jsonify({
            "status": 400,
            "message": "Error: Data must be sent as JSON.",
            "data": {}
        })

    data = request.get_json()
    name = data.get("name")
    session_data = data.get("data")

    record = db.session.query(Session).filter(Session.id == id).first()
    if name is not None:
        count = 1
        finalName = name
        while db.session.query(Session).filter(Session.name == finalName).first() != None:
            count += 1
            finalName = f"{name} ({count})"
        record.name = finalName
    if session_data is not None:
        record.data = session_data

    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Session Updated",
        "data": {
            "session": session_schema.dump(record)
        }
    })

@app.route("/session/delete/<id>", methods=["DELETE"])
def session_delete(id):
    record = db.session.query(Session).filter(Session.id == id).first()
    db.session.delete(record)
    db.session.commit()

    return jsonify({
        "status": 200,
        "message": "Session Deleted",
        "data": {
            "session": session_schema.dump(record)
        }
    })

if __name__ == "__main__":
    app.run(debug=True)