import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pyotp
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId

app = Flask(__name__)
# app.config['MONGO_URI'] = 'mongodb://rootuser:rootpass@mongodb:27017/PythonTry?authSource=admin'  # MONGO_URI for Docker network
app.config['MONGO_URI'] = 'mongodb://rootuser:rootpass@localhost:27017/PythonTry?authSource=admin'  # Updated MONGO_URI
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
    send_reset_token_email(email, reset_token)

    return jsonify({'message': 'Password reset email sent'}), 200


# Route for resetting the password
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    reset_token = request.json['ResetToken']

    # Find the user by the reset token
    user = mongo.db.users.find_one({'ResetToken': reset_token})

    if not user:
        return jsonify({'message': 'Invalid reset token or email'}), 400

    email = user['Email']

    return jsonify({'message': 'OTP verification successful', 'email': email}), 200


@app.route('/update_password', methods=['POST'])
def update_password():
    email = request.json['Email']
    new_password = request.json['NewPassword']

    # Update the password for the user
    result = mongo.db.users.update_one({'Email': email}, {'$set': {'Password': new_password, 'ResetToken': ''}})

    if result.modified_count == 1:
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'message': 'Failed to reset password'}), 500

@app.route('/users/<user_email>', methods=['PUT'])
def edit_user(user_email):
    users = mongo.db.users

    # Check if the user exists
    user = users.find_one({'Email': user_email})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Update the user data
    update_fields = {}

    if 'Email' in request.json and request.json['Email'] is not None:
        update_fields['Email'] = request.json['Email']
    if 'Password' in request.json and request.json['Password'] is not None:
        update_fields['Password'] = request.json['Password']
    if 'Address' in request.json and request.json['Address'] is not None:
        update_fields['Address'] = request.json['Address']
    if 'BloodGroup' in request.json and request.json['BloodGroup'] is not None:
        update_fields['BloodGroup'] = request.json['BloodGroup']
    if 'FirstName' in request.json and request.json['FirstName'] is not None:
        update_fields['FirstName'] = request.json['FirstName']
    if 'Gender' in request.json and request.json['Gender'] is not None:
        update_fields['Gender'] = request.json['Gender']
    if 'LastName' in request.json and request.json['LastName'] is not None:
        update_fields['LastName'] = request.json['LastName']
    if 'Number' in request.json and request.json['Number'] is not None:
        update_fields['Number'] = request.json['Number']
    if 'BirthDate' in request.json and request.json['BirthDate'] is not None:
        update_fields['BirthDate'] = request.json['BirthDate']

    # Update the user document in the database if there are fields to update
    if update_fields:
        users.update_one({'_id': user['_id']}, {'$set': update_fields})

    return jsonify({'message': 'User updated successfully'}), 200


def generate_reset_token(email):
    totp = pyotp.TOTP(pyotp.random_base32())
    reset_token = str(totp.now())[-4:]
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
    sender = 'harshsurani08@gmail.com'
    recipient = email
    subject = 'Password Reset'
    message = f'Hi, {email}!\n\nYou have requested to reset your password. Your reset token is: {reset_token}\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nThe Healthcare Team'

    send_email(sender, recipient, subject, message)

def send_email(sender, recipient, subject, message):
    # Create a MIME message object
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject

    # Attach the message to the MIME message object
    msg.attach(MIMEText(message, 'plain'))

    try:
        # Establish a connection with the SMTP server
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            # Initiate the TLS connection
            server.starttls()

            # Log in to your email account
            # in order to use this you have to add your email and get your app password from https://support.google.com/accounts/answer/185833?hl=en&authuser=1
            server.login('harshsurani08@gmail.com', 'daavshibjsvbgerg') #todo Add email and password

            # Send the email
            server.send_message(msg)
            print('Email sent successfully')
    except Exception as e:
        print('Failed to send email:', str(e))

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
    app.run(host='0.0.0.0', debug=True)
