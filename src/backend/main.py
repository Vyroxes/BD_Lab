from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from datetime import timedelta
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:5173"])

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///products.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['API_KEY'] = 'zA.w>5rtF?MscTJm,owF'  

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(100), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'product': self.product
        }

with app.app_context():
    db.create_all()

def check_api_key():
    api_key = request.headers.get('X-API-KEY')
    if api_key != app.config['API_KEY']:
        return False
    return True

@app.route('/products', methods=['GET'])
def products():
    if not check_api_key():
        return jsonify({"error": "Brak poprawnego klucza API"}), 403

    products = Products.query.all()
    products_data = [product.to_dict() for product in products]
    return jsonify(products_data), 200

@app.route('/product/<int:product_id>', methods=['GET'])
def product(product_id):
    if not check_api_key():
        return jsonify({"error": "Brak poprawnego klucza API"}), 403

    product = Products.query.get(product_id)
    if not product:
        return jsonify({"message": "Brak produktu w bazie danych."}), 404
    return jsonify(product.to_dict()), 200

@app.route('/add-product', methods=['POST'])
def add_product():
    try:
        if not check_api_key():
            return jsonify({"error": "Brak poprawnego klucza API"}), 403

        data = request.get_json()
        product_name = data.get("product")
        if not product_name or not isinstance(product_name, str) or len(product_name) < 3:
            return jsonify({"error": "Nazwa produktu musi zawierać co najmniej 3 znaki."}), 400
        
        new_product = Products(product=product_name)

        db.session.add(new_product)
        db.session.commit()
        return jsonify({"message": "Produkt dodany do bazy danych."}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Błąd podczas dodawania produktu do bazy danych."}), 500

@app.route('/delete-product/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    if not check_api_key():
        return jsonify({"error": "Brak poprawnego klucza API"}), 403

    product = Products.query.get(product_id)
    if not product:
        return jsonify({"message": "Brak produktu w bazie danych."}), 404

    db.session.delete(product)
    db.session.commit()
    return jsonify({"message": "Produkt został usunięty."}), 200

@app.route('/edit-product/<int:product_id>', methods=['PATCH'])
def edit_product(product_id):
    if not check_api_key():
        return jsonify({"error": "Brak poprawnego klucza API"}), 403

    product = Products.query.get(product_id)
    if not product:
        return jsonify({"message": "Brak produktu w bazie danych."}), 404

    data = request.get_json()
    product.product = data.get("product", product.product)

    db.session.commit()
    return jsonify({"message": "Produkt zaktualizowany."}), 200

if __name__ == '__main__':
    app.run(debug=True)