from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId

app = Flask(__name__)
app.config['MONGO_URI'] = 'mongodb://rootuser:rootpass@localhost:27017/PythonTry?authSource=admin'
app.config['JWT_SECRET_KEY'] = 'JBcnvFSv0R1HSJFNE_kUF-yMAm6vTE4EpzR_CrmjC6w'
mongo = PyMongo(app)
jwt = JWTManager(app)

@app.route('/signup', methods=['POST'])
def signup():
    users = mongo.db.users

    # Check if the email already exists
    if users.find_one({'Email': request.json['Email']}):
        return jsonify({'message': 'Email already exists'}), 409

    # Create a new user
    user = {
        'Email': request.json['Email'],
        'Password': request.json['Password'],
        'Address': request.json['Address'],
        'BloodGroup': request.json['BloodGroup'],
        'FirstName': request.json['FirstName'],
        'Gender': request.json['Gender'],
        'LastName': request.json['LastName'],
        'Number': request.json['Number'],
        'BirthDate': request.json['BirthDate']
    }

    users.insert_one(user)

    # Generate an access token for the newly registered user
    access_token = create_access_token(identity=request.json['Email'])

    return jsonify({'message': 'User created successfully', 'access_token': access_token}), 201

@app.route('/login', methods=['POST'])
def login():
    users = mongo.db.users
    email = request.json['Email']
    password = request.json['Password']

    # Check if the email and password match
    user = users.find_one({'Email': email, 'Password': password})
    if not user:
        return jsonify({'message': 'Invalid email or password'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity=email)
    return jsonify({'access_token': access_token}), 200

@app.route('/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    email = get_jwt_identity()

    # Retrieve the user data from the database based on the email
    user = mongo.db.users.find_one({'Email': email})

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Remove the '_id' field as it is not JSON serializable
    user.pop('_id')

    return jsonify(user), 200


@app.route('/users', methods=['GET'])
def get_users():
    users = mongo.db.users.find()
    users_list = []
    for user in users:
        user['_id'] = str(user['_id'])  # Convert ObjectId to string
        users_list.append(user)
    return jsonify({'users': users_list})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
