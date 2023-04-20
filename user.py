from flask import Blueprint, request, make_response
from google.cloud import datastore
import json
import constants

client = datastore.Client()

bp = Blueprint('user', __name__, url_prefix='/users')

@bp.route('', methods=['GET'])
def get_users():
    if request.method == 'GET':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        query = client.query(kind="users")
        usersList = list(query.fetch())
        return ({"users": usersList}, 200)
    else:
        response = make_response({"Error": "Method Not Allowed"})
        response.headers.set('Allow', 'GET')
        response.headers.set('Content-Type', 'application/json')
        response.status_code = 405
        return response
