from flask import Flask, render_template, request, jsonify, abort
from flask_restful import Resource, Api
from pymongo import MongoClient
import os
import logging # Debug using
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer \
                                  as Serializer, BadSignature, \
                                  SignatureExpired)
import time
import logging      # Debugging Purpose


app = Flask(__name__)
client = MongoClient('mongodb://' + os.environ['MONGODB_HOSTNAME'], 27017)
ourdb =  client.tododb      # DB for storing Brevets time data
userdb = client.users       # DB for storing User Info

api = Api(app)
SECRET_KEY = 'test1234@#$'


class listAll(Resource):
    """
        In this class, it pulls all brevets time data that stored in the database and bring them back 
        to the client side.

        For project 7, we should get the token from the client side and verify it for security reason.
        If passed the verification, then pull the requested data. Otherwise, return error code 401.
    """
    def csv_form(self):
        output = ""
        # The first line
        data = list(ourdb.tododb.find({},{"_id":0, "open_time_field":1, "close_time_field":1}))
        firstline = list(data[0].keys())
        output = ",".join(firstline)
        output += "\n"
        #Rest of lines
        for d in data:
            output += ",".join(list(d.values()))
            output += "\n"
        return output
    
    def json_form(self):
        return list(ourdb.tododb.find({},{"_id":0, "open_time_field":1, "close_time_field":1}))
   
    def get(self, dataType="json"):     
        getToken = request.args.get('token')
        # app.logger.debug("TOKEN ===>   ", getToken)           #Testing
        verified = verify_auth_token(getToken)
        # app.logger.debug("Verified TOKEN ===>   ", verified)  #Testing
        if verified:
            if dataType == "csv":
                return self.csv_form()
            return self.json_form()
        else:
            return 401
        
class listOpenOnly(Resource):
    """
        In this class, it pulls only open brevets time that stored in the database with a quantity that 
        the user wants and bring them back to the client side.

        For project 7, we should get the token from the client side and verify it for security reason.
        If passed the verification, then pull the requested data. Otherwise, return error code 401.
    """
    def csv_form(self, qty):
        temp = []
        output = ""
        # The first line
        data = list(ourdb.tododb.find({},{"_id":0, "open_time_field":1}))
        firstline = list(data[0].keys())
        output = ",".join(firstline)
        output += "\n"

        #Rest of lines
        if qty > 0 and qty <= len(data):
            for i in range(qty):
                temp.append(dict(data[i]))
            for d in temp:
                output += ",".join(list(d.values()))
                output += "\n"
        else:
            temp = data
            for d in temp:
                output += ",".join(list(d.values()))
                output += "\n"
        return output
    
    def json_form(self, qty):
        temp = []
        data = list(ourdb.tododb.find({},{"_id":0, "open_time_field":1}))
        if qty > 0 and qty <= len(data):
            for i in range(qty):
                temp.append(dict(data[i]))
        else:
            temp = data
        return temp
            
    def get(self, dataType="json"):
        token = request.args.get('token')
        # app.logger.debug("TOKEN ===>   ", token)
        verified = verify_auth_token(token)
        # app.logger.debug("Verified TOKEN ===>   ", verified)
        if verified:
            qty = int(request.args.get("top", default=0, type=int))
            if dataType == "csv":
                return self.csv_form(qty)
            return self.json_form(qty)
        else:
            return 401

# Handling close time, similar to the logic where used in handling open time
class listCloseOnly(Resource):
    """
        In this class, it pulls only close brevets time that stored in the database with a quantity that 
        the user wants and bring them back to the client side.

        For project 7, we should get the token from the client side and verify it for security reason.
        If passed the verification, then pull the requested data. Otherwise, return error code 401.
    """
    def csv_form(self, qty):
        temp = []
        output = ""
        # The first line
        data = list(ourdb.tododb.find({},{"_id":0, "close_time_field":1}))
        firstline = list(data[0].keys())
        output = ",".join(firstline)
        output += "\n"

        #Rest of lines
        if qty > 0 and qty <= len(data):
            for i in range(qty):
                temp.append(dict(data[i]))
            for d in temp:
                output += ",".join(list(d.values()))
                output += "\n"
        else:
            temp = data
            for d in temp:
                output += ",".join(list(d.values()))
                output += "\n"
        return output
    
    def json_form(self, qty):
        temp = []
        data = list(ourdb.tododb.find({},{"_id":0, "close_time_field":1}))
        if qty > 0 and qty <= len(data):
            for i in range(qty):
                temp.append(dict(data[i]))
        else:
            temp = data
        return temp
            
    def get(self, dataType="json"):
        token = request.args.get('token')
        verified = verify_auth_token(token)
        if verified:
            qty = int(request.args.get("top", default=0, type=int))
            if dataType == "csv":
                return self.csv_form(qty)
            return self.json_form(qty)
        else:
            return 401

class register(Resource):
    def post(self):
        # Gets the username and password
        username = request.form.get("username", type=str)
        password = request.form.get("password", type=str)

        # If the username already exist
        if userdb.users.find_one({"username": username}):
            # Or directly return an error message
            return abort(400)
        else:
            # Then hashed the password and store into database.
            encryptedPW = hash_password(password)
            userdb.users.insert({"username":username, "password": encryptedPW})
            return "SUCCESS", 201

# Login
class token(Resource):
    def get(self):
        # Gets the username and password
        username = request.args.get("username", type=str)
        password = request.args.get("password", type=str)

        current_user = userdb.users.find_one({"username": username})
        if not current_user:    # If not find the username in db
            return abort(401)
        if not verify_password(password, current_user["password"]):
            return abort(401)   # Incorrect PW
        else:
            token = generate_auth_token(username).decode('utf-8')
            return {"token" : token, "username": username, "id" : str(current_user["_id"])}, 200


def hash_password(password):
    return pwd_context.encrypt(password)


def verify_password(password, hashVal):
    return pwd_context.verify(password, hashVal)

def generate_auth_token(username, expiration=120):
   s = Serializer(SECRET_KEY, expires_in=expiration)
   return s.dumps({"username":username})


def verify_auth_token(token):
    s = Serializer(SECRET_KEY)
    try:
        data = s.loads(token)
    except SignatureExpired:
        return False    # valid token, but expired
    except BadSignature:
        return False    # invalid token
    return True

api.add_resource(listAll, '/listAll', '/listAll/<string:dataType>')
# api.add_resource(listAll, '/listAll/<str:dataType>')

api.add_resource(listOpenOnly, '/listOpenOnly', '/listOpenOnly/<string:dataType>')
# api.add_resource(listOpenOnly, '/listOpenOnly/<str:dataType>')

api.add_resource(listCloseOnly, '/listCloseOnly', '/listCloseOnly/<string:dataType>')
# api.add_resource(listCloseOnly, '/listCloseOnly/<str:dataType>')\

api.add_resource(register, '/register', '/register/')

api.add_resource(token, '/token', '/token/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)