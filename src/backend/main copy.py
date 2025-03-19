from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import timedelta
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
CORS(app, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'zA.w>5rtF?MscTJm,owF'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=5)
app.config['JWT_ACCESS_TOKEN_REMEMBER_EXPIRES'] = timedelta(days=7)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(320), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    products = db.relationship('Products', backref='owner', lazy=True)

class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product = db.Column(db.String(100), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.product
        }

with app.app_context():
    db.create_all()

@app.route('/products', methods=['GET'])
@jwt_required()
def products():
    user_id = get_jwt_identity()
    products = Products.query.filter_by(user_id=user_id).all()

    products_data = [product.to_dict() for products in products]

    return jsonify(products_data), 200

@app.route('/product/<int:product_id>', methods=['GET'])
@jwt_required()
def product(product_id):
    user_id = get_jwt_identity()
    product = Products.query.filter_by(id=product_id, user_id=user_id).first()
    if not product:
        return jsonify({"message": "Brak produktu w bazie danych."}), 404

    product_data = product.to_dict()

    return jsonify(product_data), 200


@app.route('/add-product', methods=['POST'])
@jwt_required()
def add_product():
    try:
        existing_product = Products.query.filter_by(isbn=request.json['product']).first()
        if existing_product:
            return jsonify({"error": "Produkt o tej nazwie już istnieje w bazie danych."}), 400

        user_id = get_jwt_identity()
        data = request.get_json()

        new_product = Products(user_id=user_id, **data)
        db.session.add(new_product)
        db.session.commit()
        return jsonify({"message": "Produkt dodany do bazy danych."}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Błąd podczas dodawania produktu do bazy danych."}), 500

@app.route('/delete-product/<int:product_id>', methods=['PUT'])
@jwt_required()
def delete_product(product_id):
    user_id = get_jwt_identity()
    product = Products.query.filter_by(id=product_id, user_id=user_id).first()
    if not product:
        return jsonify({"message": "Brak produktu w bazie danych."}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Produkt został usunięty."}), 200

@app.route('/edit-product/<int:product_id>', methods=['PATCH'])
@jwt_required()
def edit_product(product_id):
    user_id = get_jwt_identity()
    product = Products.query.filter_by(id=product_id, user_id=user_id).first()
    if not product:
        return jsonify({"message": "Brak produktu w bazie danych."}), 404

    data = request.get_json()
    product.name = data.get("name")

    db.session.commit()
    return jsonify({"message": "Produkt zaktualizowany."}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('usernameOrEmail')).first() or User.query.filter_by(username=data.get('usernameOrEmail')).first()

    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        if data.get('remember'):
            access_token_expires = app.config['JWT_ACCESS_TOKEN_REMEMBER_EXPIRES']
        else:
            access_token_expires = app.config['JWT_ACCESS_TOKEN_EXPIRES']

        access_token = create_access_token(identity=str(user.id), expires_delta=access_token_expires)

        response = make_response(jsonify({
            "message": "Logowanie pomyślne",
            "username": user.username,
            "email": user.email,
            "access_token": access_token,
            "expire_time": str(access_token_expires),
        }))

        response.set_cookie("access_token", access_token, httponly=False, samesite='Lax', secure=True)

        return response, 200
    
    return jsonify({"message": "Niepoprawne dane."}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if User.query.filter_by(username=data.get('username')).first():
        return jsonify({"message": "Nazwa użytkownika jest już zajęta."}), 400
    
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"message": "Email jest już zajęty."}), 400

    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')

    new_user = User(username=data.get('username'), email=data.get('email'), password=hashed_password)
    
    try:
        db.session.add(new_user)
        db.session.commit()

        access_token_expires = app.config['JWT_ACCESS_TOKEN_EXPIRES']

        access_token = create_access_token(identity=str(new_user.id), expires_delta=access_token_expires)

        response = make_response(jsonify({
            "message": "Rejestracja pomyślna",
            "username": new_user.username,
            "email": new_user.email,
            "access_token": str(access_token),
            "expire_time": str(access_token_expires),
        }))

        response.set_cookie("access_token", access_token, httponly=False, samesite='Lax', secure=True)

        return response, 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Błąd podczas rejestracji: " + str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)