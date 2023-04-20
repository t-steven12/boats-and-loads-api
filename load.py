from flask import Blueprint, request, make_response
from google.cloud import datastore
import json
import constants

APP_URL = "https://boat-load-api-stieu.wl.r.appspot.com"

client = datastore.Client()

bp = Blueprint('load', __name__, url_prefix='/loads')

@bp.route('', methods=['POST','GET'])
def loads_get_post():
    if request.method == 'POST':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        content = request.get_json()
        content_keys = content.keys()
        if len(content_keys) != 3 or 'volume' not in content_keys or 'item' not in content_keys or 'creation_date' not in content_keys:
            return ({'Error': "The request object is missing at least one of the required attributes or includes an extraneous/invalid attribute"}, 400)
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"volume": content["volume"], "carrier": None, "item": content["item"], "creation_date": content["creation_date"]})
        client.put(new_load)
        new_load.update({"self": APP_URL + "/loads/" + str(new_load.key.id)})
        client.put(new_load)
        new_load.update({"id": new_load.key.id})
        return (new_load, 201) 
    elif request.method == 'GET':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        query = client.query(kind=constants.loads)
        lim = int(request.args.get('limit', '5'))
        off = int(request.args.get('offset', '0'))
        loads_iterator = query.fetch(limit=lim, offset=off)
        pages = loads_iterator.pages
        results = list(next(pages))
        if loads_iterator.next_page_token:
            next_off = off + lim
            next_url = request.base_url + "?limit=" + str(lim) + "&offset=" + str(next_off)
        else:
            next_url = None
        for load in results:
            load["id"] = load.key.id
        loadsList = {"loads": results}
        if next_url:
            loadsList["next"] = next_url
        query2 = list(query.fetch())
        loadsList["total_number_of_loads"] = len(query2)
        return loadsList
    else:
        response = make_response({"Error": "Method Not Allowed"})
        response.headers.set('Allow', 'POST, GET')
        response.status_code = 405
        return response


@bp.route('/<load_id>', methods=['GET', 'PUT', 'PATCH', 'DELETE'])
def manageOneLoad_get_put_delete(load_id):
    if request.method == 'GET':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if load is None:
            return ({'Error': 'No load with this load_id exists'}, 404)
        load.update({'id': int(load_id)})
        return (load, 200)
    if request.method == 'PUT':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        content = request.get_json()
        content_keys = content.keys()
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if load is None:
            return ({'Error': 'No load with this load_id exists'}, 404)
        if len(content_keys) != 3 or 'volume' not in content_keys or 'item' not in content_keys or 'creation_date' not in content_keys:
            return ({'Error': "The request object is missing at least one of the required attributes or includes an extraneous/invalid attribute"}, 400)
        load.update({'volume': content['volume'], 'item': content['item'], 'creation_date': content['creation_date']})
        client.put(load)
        load.update({'id': int(load_id)})
        return (load, 200)
    if request.method == 'PATCH':
        if "application/json" not in request.accept_mimetypes:
            return ({"Error": "Not Acceptable. Must accept JSON."}, 406)
        content = request.get_json()
        content_keys = content.keys()
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if load is None:
            return ({'Error': 'No load with this load_id exists'}, 404)
        if len(content_keys) > 3 or len(content_keys) < 1:
            return ({'Error': "The request object is missing a valid attribute or includes an extraneous/invalid attribute"}, 400)
        for key in content_keys:
            if key == 'volume':
                load.update({'volume': content["volume"]})
            elif key == 'item':
                load.update({'item': content['item']})
            elif key == 'creation_date':
                load.update({'creation_date': content['creation_date']})
            else:
                return ({'Error': "The request object is missing a valid attribute or includes an extraneous/invalid attribute"}, 400)
        client.put(load)
        load.update({'id': int(load_id)})
        return (load, 200)
    elif request.method == 'DELETE':
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if load is None:
            return ({'Error': "No load with this load_id exists"}, 404)
        if load['carrier'] is not None:
            boat_key = client.key(constants.boats, load['carrier']['id'])
            boat = client.get(key=boat_key)
            for load in boat['loads']:
                if load["id"] == int(load_id):
                    boat['loads'].remove(load)
                    client.put(boat)
                    break
        else:
            return ({'Error': "No load with this load_id exists"}, 404)
        client.delete(load_key)
        return ('',204)
    else:
        response = make_response({"Error": "Method Not Allowed"})
        response.headers.set('Allow', 'GET, PUT, PATCH, DELETE')
        response.status_code = 405
        return response