from flask import Flask, request, jsonify, session
from flask_session import Session
import redis
import hashlib
import uuid
import requests
import json

app = Flask(__name__)
app.secret_key = 'ballzinyojawz'

MICROSERVICE_URL = 'http://localhost:8080/api'

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url('redis://localhost:6380')
Session(app)

db = redis.Redis(host='localhost', port=6380, db=0)

def init():
    db.flushdb()

def clear_sessions():
    for key in db.keys('session:*'):
        db.delete(key)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate():
    username = session.get('username')
    token = session.get('token')
    print("hello")
    print(username)
    print(token)
    if username and token:
        stored_token = session.get('session:' + username)
        print(stored_token)
        if stored_token and stored_token == token:
            return True
    return False

@app.route('/is_logged_in', methods=['GET'])
def is_logged_in():
    if 'username' in session:
        return jsonify({"message": "User is logged in"}), 200
    else:
        return jsonify({"message": "User is not logged in"}), 200

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    age = request.json.get('age')
    currency = request.json.get('currency_type')

    if age < 18:
        return jsonify({"error": "Age must be at least 18"}), 400

    if db.get(username):
        return jsonify({"error": "Username already exists"}), 400

    hashed_password = hash_password(password)
    # db.set(key, value)
    db.set(username, json.dumps({"password": hashed_password, "age": age, "currency_type": currency}))

    return jsonify({"message": "User registered successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    session['username'] = username
    token = str(uuid.uuid4())
    session['token'] = token
    session['session:' + username] = token
    return jsonify({"message": "Logged in successfully"}), 200

@app.route('/logout', methods=['POST'])
def logout():
    username = session.get('username')
    if username:
        session.pop('username', None)
        session.pop('token', None)
        session.pop('session:' + username, None)
        return jsonify({"message": username + " logged out successfully"}), 200
    return jsonify({"message": "No user is logged in"}), 200

@app.route('/balance/', methods=['GET'])
def get_balance():
    if not authenticate():
        return jsonify({"error": "User not authenticated"}), 401

    userId = session.get('username')

    response = requests.get((f"{MICROSERVICE_URL}/balance/{userId}"))
    return {"balance": response.json()}

@app.route('/add/balance', methods=['POST'])
def add_balance():
    if not authenticate():
        return jsonify({"error": "User not authenticated"}), 401

    userId = session.get('username')
    amount = int(request.json.get('amount'))

    if amount < 0:
        return jsonify({"error": "Amount must be positive"}), 400


    data = {'userId': userId, 'amount': amount}
    response = requests.post(MICROSERVICE_URL + '/add/balance', json=data)
    return {"balance": response.json()}

@app.route('/buy', methods=['POST'])
def buy():
    if not authenticate():
        return jsonify({"error": "User not authenticated"}), 401

    amount = int(request.json.get('amount'))

    if amount < 0:
        return jsonify({"error": "Amount must be positive"}), 400

    data = {'userId': session.get('username'), 'coinId': request.json.get('coinId'), 'amount': amount}
    response = requests.post(MICROSERVICE_URL + '/buy', json=data)
    if response.text.strip():  # Check if the response is not empty
        try:
            return response.json()
        except ValueError:
            return jsonify({"error": "Invalid response from server"}), 500
    else:
        return jsonify({"message": "Not enough balance"}), 200

@app.route('/sell', methods=['POST'])
def sell():
    if not authenticate():
        return jsonify({"error": "User not authenticated"}), 401

    amount = int(request.json.get('amount'))

    if amount < 0:
        return jsonify({"error": "Amount must be positive"}), 400

    if (request.json.get('coinId') == None):
        return jsonify({"error": "Coin ID is required"}), 400

    data = {'userId': session.get('username'), 'coinId': request.json.get('coinId'), 'amount': amount}
    response = requests.post(MICROSERVICE_URL + '/sell', json=data)

    if response.text.strip():  # Check if the response is not empty
        try:
            return response.json()
        except ValueError:
            return jsonify({"error": "Invalid response from server"}), 500
    else:
        return jsonify({"message": "Not enough coin amount"}), 200

if __name__ == '__main__':
    clear_sessions()
    app.run(debug=True)