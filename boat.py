# The following code is based on/derived from the "main.py" file provided by the Fall 2022 Cloud Application Development course(CS493) at Oregon State University
# on the "Exploration - Authentication in Python" webpage linked here: https://canvas.oregonstate.edu/courses/1890665/pages/exploration-authentication-in-python?module_item_id=22486484

from flask import request, make_response, Blueprint
from google.cloud import datastore
import json
import constants

from flask import Flask, request, render_template

from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, render_template
import requests

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

client = datastore.Client()

APP_URL = "https://boat-load-api-stieu.wl.r.appspot.com"

# Update the values of the following 3 variables
CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = ''
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

bp = Blueprint('boat', __name__, url_prefix='/boats')

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@bp.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

@bp.route('', methods=['POST','GET'])
def boats_get_post():
    if request.method == 'POST':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        payload = verify_jwt(request)
        content = request.get_json()
        content_keys = content.keys()
        if len(content_keys) != 3 or 'name' not in content_keys or 'type' not in content_keys or 'length' not in content_keys:
            return ({'Error': "The request object is missing at least one of the required attributes or includes an extraneous/invalid attribute"}, 400)
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        print(new_boat)
        new_boat.update({'name': content['name'], 'type': content['type'], 'length': content['length'], 'owner': payload['sub'],  'loads': []})
        client.put(new_boat)
        new_boat.update({'self': APP_URL + '/boats/' + str(new_boat.key.id)})
        client.put(new_boat)
        new_boat.update({'id': new_boat.key.id})
        return (new_boat, 201)
    elif request.method == 'GET':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        # still need to make self links
        payload = verify_jwt(request)
        decodedJWT = requests.get(APP_URL + '/decode', headers={'Authorization': request.headers['Authorization']})
        decodedJWT = decodedJWT.json()
        listOfOwnerBoats = []
        query = client.query(kind='boats')
        boatsList = list(query.fetch())
        numberOfOwnerBoats = 0
        for boat in boatsList:
            if boat['owner'] == decodedJWT['sub']:
                boat["id"] = boat.key.id
                listOfOwnerBoats.append(boat)
                numberOfOwnerBoats += 1
        lim = int(request.args.get('limit', '5'))
        off = int(request.args.get('offset', '0'))
        paginatedList = []
        currentIndex = 0
        for boat in listOfOwnerBoats:
            if len(paginatedList) == 5:
                break
            if currentIndex >= off:
                paginatedList.append(boat)
            currentIndex += 1
        toReturn = {}
        if currentIndex == numberOfOwnerBoats:
            toReturn.update({"boats": paginatedList, "total_number_of_boats": numberOfOwnerBoats})
        else:
            toReturn.update({"boats": paginatedList, "total_number_of_boats": numberOfOwnerBoats, "next": APP_URL + "/boats?" + "limit=5&" + "offset=" + str(lim + off)})
        return (toReturn, 200)
    else:
        response = make_response({"Error": "Method Not Allowed"})
        response.headers.set('Allow', 'GET, POST')
        response.headers.set('Content-Type', 'application/json')
        response.status_code = 405
        return response

@bp.route('/<boat_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def manageOneBoat_get_put_delete(boat_id):
    if request.method == 'GET':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if boat is None:
            return ({'Error': "No boat with this boat_id exists"}, 404)
        if boat['owner'] != payload['sub']:
            return ({'Error': "Viewing this boat is not allowed for this user"}, 403)
        boat.update({'id': int(boat_id)})
        return boat
    elif request.method == 'DELETE':
        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if boat is None:
            return ({'Error': "No boat with this boat_id exists"}, 404)
        if boat['owner'] != payload['sub']:
            return ({'Error': "Deleting this boat is not allowed for this user"}, 403)
        for l in boat['loads']:
            load_key = client.key(constants.loads, l['id'])
            load = client.get(key=load_key)
            load['carrier'] = None
            client.put(load)
        client.delete(boat_key)
        return ('',204)
    elif request.method == 'PUT':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if boat is None:
            return ({'Error': "No boat with this boat_id exists"}, 404)
        if boat['owner'] != payload['sub']:
            return ({'Error': "Editing/updating this boat is not allowed for this user"}, 403)  
        content = request.get_json()
        content_keys = content.keys()
        if len(content_keys) != 3 or 'name' not in content_keys or 'type' not in content_keys or 'length' not in content_keys:
            return ({'Error': "The request object is missing at least one of the required attributes or includes an extraneous/invalid attribute"}, 400)
        if boat is None:
            return ({'Error': "No boat with this boat_id exists"}, 404)
        boat.update({'name': content['name'], 'type': content['type'], 'length': content['length']})
        client.put(boat)
        boat.update({'id': int(boat_id)})
        return (boat, 200)
    elif request.method == 'PATCH':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        payload = verify_jwt(request)
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if boat is None:
            return ({'Error': "No boat with this boat_id exists"}, 404)
        if boat['owner'] != payload['sub']:
            return ({'Error': "Editing/updating this boat is not allowed for this user"}, 403)  
        content = request.get_json()
        content_keys = content.keys()
        if len(content_keys) > 3 or len(content_keys) < 1:
            return ({'Error': "The request object is missing a valid attribute or includes an extraneous/invalid attribute"}, 400)
        for key in content_keys:
            if key == 'name':
                boat.update({"name": content["name"]})
            elif key == 'type':
                boat.update({'type': content['type']})
            elif key == 'length':
                boat.update({'length': content['length']})
            else:
                return ({'Error': "The request object is missing a valid attribute or includes an extraneous/invalid attribute"}, 400)
        client.put(boat)
        boat.update({'id': int(boat_id)})
        return (boat, 200)
    else:
        response = make_response({"Error": "Method Not Allowed"})
        response.headers.set('Allow', 'GET, PUT, PATCH, DELETE')
        response.status_code = 405
        return response
        

@bp.route('/<boat_id>/loads/<load_id>', methods=['PUT','DELETE'])
def assignment_load_boat(boat_id,load_id):
    if request.method == 'PUT':
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if boat is None or load is None:
            return ({'Error': "The specified boat and/or load does not exist"}, 404)
        if load['carrier'] is not None:
            return ({'Error': "The load is already loaded on another boat"}, 403)
        boat['loads'].append({"id": int(load_id), "self": load["self"]})
        load['carrier'] = {"id": int(boat_id), "name": boat['name'], "self": boat['self']}
        client.put(boat)
        client.put(load)
        return('', 204)
    if request.method == 'DELETE':
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if boat is None or load is None:
            return ({'Error': "No boat with this boat_id is loaded with the load with this load_id"}, 404)
        for l in boat['loads']:
            if l["id"] == int(load_id):
                boat['loads'].remove({"id": int(load_id), "self": load["self"]})
                load['carrier'] = None
                client.put(boat)
                client.put(load)
                return('',204)
        return({'Error': "No boat with this boat_id is loaded with the load with this load_id"}, 404)
    else:
        response = make_response({"Error": "Method Not Allowed"})
        response.headers.set('Allow', 'PUT, DELETE')
        response.status_code = 405
        return response
