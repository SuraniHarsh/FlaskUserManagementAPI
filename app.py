import pyotp
from flask_mail import Mail,Message
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId

app = Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = '' #Enter your Email
app.config['MAIL_PASSWORD'] = '' #Enter your PassWord
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

app.config['MONGO_URI'] = 'mongodb://rootuser:rootpass@localhost:27017/PythonTry?authSource=admin' #Enter your MONGO_URL
app.config['JWT_SECRET_KEY'] = 'JBcnvFSv0R1HSJFNE_kUF-yMAm6vTE4EpzR_CrmjC6w' #Enter YOur JWT KEY
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


# Route for password reset request
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    email = request.json['Email']

    # Check if the email exists in the database
    user = mongo.db.users.find_one({'Email': email})
    if not user:
        return jsonify({'message': 'Email not found'}), 404

    # Generate a password reset token
    reset_token = generate_reset_token(email)

    # Save the reset token in the database
    save_reset_token(email, reset_token)

    # Send the password reset email to the user
    send_reset_token_email(email, reset_token) #TODO setup mail server for sendig OTP

    return jsonify({'message': 'Password reset email sent'}), 200


# Route for resetting the password
@app.route('/reset_password', methods=['POST'])
def reset_password():
    reset_token = request.json['OTP']
    new_password = request.json['NewPassword']

    # Find the user by the reset token
    user = mongo.db.users.find_one({'ResetToken': reset_token})

    if not user:
        return jsonify({'message': 'Invalid reset token or email'}), 400

    email = user['Email']

    # Update the password for the user
    result = mongo.db.users.update_one({'Email': email}, {'$set': {'Password': new_password, 'ResetToken': ''}})

    if result.modified_count == 1:
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'message': 'Failed to reset password'}), 500
def generate_reset_token(email):
    totp = pyotp.TOTP(pyotp.random_base32())
    reset_token = totp.now()
    return reset_token

# Function to save the reset token in the database
def save_reset_token(email, reset_token):
    users = mongo.db.users

    # Update the user document with the reset token
    result = users.update_one({'Email': email}, {'$set': {'ResetToken': reset_token}})

    if result.modified_count == 1:
        return jsonify({'message': 'Reset token saved successfully'}), 200
    else:
        return jsonify({'message': 'Failed to save reset token'}), 500

# Function to send the password reset email
def send_reset_token_email(email, reset_token):
    subject = 'Password Reset OTP'
    body = f'Hi, {email}!\n\nYou have requested to reset your password. Your OTP is: {reset_token}\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nThe Healthcare Team'

    # Create the message object
    message = Message(subject=subject, recipients=[email], body=body)

    try:
        # Send the email
        print(message)
        mail.send(message)
        return jsonify({'message': 'Reset token email sent successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'Failed to send reset token email'}), 500

# Function to check if the reset token is valid
def is_valid_reset_token(email, reset_token):
    users = mongo.db.users

    # Check if the email and reset token match
    user = users.find_one({'Email': email, 'ResetToken': reset_token})

    if user:
        return jsonify({'message': 'Valid reset token'}), 200
    else:
        return jsonify({'message': 'Invalid reset token'}), 401

# Function to update the password in the database
def update_password(email, new_password):
    users = mongo.db.users

    # Find the user by email
    user = users.find_one({'Email': email})

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Update the password
    user['Password'] = new_password
    users.save(user)

    return jsonify({'message': 'Password updated successfully'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
