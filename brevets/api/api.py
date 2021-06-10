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


app = Flask(__name__)
client = MongoClient('mongodb://' + os.environ['MONGODB_HOSTNAME'], 27017)
ourdb =  client.tododb
userdb = client.users

api = Api(app)
SECRET_KEY = 'test1234@#$'


class listAll(Resource):
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
        if dataType == "csv":
            return self.csv_form()
        return self.json_form()
        

class listOpenOnly(Resource):
    
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
        qty = int(request.args.get("top", default=0, type=int))
        if dataType == "csv":
            return self.csv_form(qty)
        return self.json_form(qty)


# Handling close time, similar to the logic where used in handling open time
class listCloseOnly(Resource):

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
        qty = int(request.args.get("top", default=0, type=int))
        if dataType == "csv":
            return self.csv_form(qty)
        return self.json_form(qty)

class register(Resource):
    def post(self):
        username = request.form.get("username", type=str)
        password = request.form.get("password", type=str)
        # Or it's not necessary to convert find() to a list
        # If pop up error(s), replace the line below with find_one()
        if len(list(userdb.users.find({"username": username}))) != 0:
            # Or directly return an error message
            return abort(400)
        # This elif statement seems redundent.
        elif password == "":
            return abort(400)
        else:
            encryptedPW = hash_password(password)
            userdb.users.insert_one({"username"[username], "password"[encryptedPW]})
            return "SUCCESS", 201


class login():
    def get(self):
        username = request.form.get("username", type=str)
        password = request.form.get("password", type=str)

        # Or it's not necessary to convert find() to a list
        # If pop up error(s), replace the line below with find_one()
        if len(list(userdb.users.find({"username": username}))) == 0:
            return abort(400)
        elif password == "":
            return abort(400)
        encryptedPW = hash_password(password)
        db = userdb.users.find({"username": username, "password":encryptedPW})
        if db == []:
            return abort(400) # Incorrect PW
        return generate_auth_token(), 200


def hash_password(password):
    return pwd_context.encrypt(password)


def verify_password(password, hashVal):
    return pwd_context.verify(password, hashVal)

def generate_auth_token(expiration=600):
   s = Serializer(SECRET_KEY, expires_in=expiration)
   return s.dumps({'id': 5, 'name': 'Ryan'})


def verify_auth_token(token):
    s = Serializer(SECRET_KEY)
    try:
        data = s.loads(token)
    except SignatureExpired:
        return "Expired token!"    # valid token, but expired
    except BadSignature:
        return "Invalid token!"    # invalid token
    return f"Success! Welcome {data['username']}."

api.add_resource(listAll, '/listAll', '/listAll/<string:dataType>')
# api.add_resource(listAll, '/listAll/<str:dataType>')

api.add_resource(listOpenOnly, '/listOpenOnly', '/listOpenOnly/<string:dataType>')
# api.add_resource(listOpenOnly, '/listOpenOnly/<str:dataType>')

api.add_resource(listCloseOnly, '/listCloseOnly', '/listCloseOnly/<string:dataType>')
# api.add_resource(listCloseOnly, '/listCloseOnly/<str:dataType>')\

api.add_resource(register, '/register')

api.add_resource(login, '/login')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)