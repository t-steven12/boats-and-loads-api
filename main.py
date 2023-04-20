# The following code is based on/derived from the "main.py" file provided by the Fall 2022 Cloud Application Development course(CS493) at Oregon State University
# on the "Exploration - Authentication in Python" webpage linked here: https://canvas.oregonstate.edu/courses/1890665/pages/exploration-authentication-in-python?module_item_id=22486484
 
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
import user
import boat
import load

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

APP_URL = "https://boat-load-api-stieu.wl.r.appspot.com"

# Update the values of the following 3 variables
CLIENT_ID = ''
CLIENT_SECRET = ''
DOMAIN = ''
# For example
# DOMAIN = 'fall21.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
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

app.register_blueprint(boat.bp)
app.register_blueprint(load.bp)
app.register_blueprint(user.bp)

@app.route('/')
def index():
    return render_template("index.html")

# *******BEGIN CITED CODE*******
# The following code is not my original code and has been adapted from the source below.
# SOURCE: https://auth0.com/docs/quickstart/webapp/python
# The code starts by setting up a Flask route/endpoint for beginning an Auth0 authentication/authorization flow using
# "@app.route('/login')". The function "login()" is then defined which executes when a user of the app is
# directed to the URL for the "/login" route/endpoint below. Inside the "login()" func., a function "oauth.auth0.authorize_redirect()"
# is returned which will redirect the user to an Auth0 login/sign-up page for user login or creation to begin the 
# authentication/authorization process. The function has the argument "redirect_uri=url_for("display_user", _external=True)"
# which sets the redirect URI/URL where the user will be directed to after the authentication/authorization process is finished.
# In this case, the redirect URI/URL is the URI/URL for the "display_user" function which is the URI/URL for the route/endpoint of '/userInfo'
# (you can see this route below the '/login' route). The page of the redirect URI/URL is where a JWT token for the logged-in user will be displayed.
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("display_user", _external=True)
    )
# ********END CITED CODE********

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload      

# Generate a JWT from the Auth0 domain and return it
@app.route('/userInfo')
def display_user():
    body = {'grant_type':'authorization_code',
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET,
            'code': request.args.get('code'),
            'redirect_uri': APP_URL + '/userInfo'
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    print(r.json())
    decodedJWT = requests.get(APP_URL + '/decode', headers={'Authorization': "Bearer " + r.json()['id_token']})
    print(decodedJWT.json())
    decodedJWT = decodedJWT.json()
    userInfoToSend = {"token": r.json()['id_token'], "id": decodedJWT['sub']}
    query = client.query(kind='users')
    usersList = list(query.fetch())
    print(usersList) #debugging list of users
    if usersList == []:
        new_user = datastore.entity.Entity(key=client.key('users'))
        new_user.update({"unique_id": decodedJWT["sub"], "name": decodedJWT["name"]})
        client.put(new_user)
    else:
        userExists = False
        for user in usersList:
            if user["name"] == decodedJWT["name"]:
                userExists = True
        if userExists == False:
            new_user = datastore.entity.Entity(key=client.key('users'))
            new_user.update({"unique_id": decodedJWT["sub"], "name": decodedJWT["name"]})
            client.put(new_user)            
    return render_template("user_info.html", userInfo=userInfoToSend)




if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)