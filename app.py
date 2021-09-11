import hmac
import hashlib
import json
import os

from flask import Flask
from flask import request
import requests
import requests.auth


app = Flask(__name__)
app.config.from_json('config.json')


@app.route("/", methods=['GET', 'POST'])
def index():
    body = request.data
    signature = request.headers['x-pyrus-sig']
    secret = str.encode(app.config['SECRET_KEY'])

    if _is_signature_correct(body, secret, signature):
        return _prepare_response(body.decode('utf-8'))


def _is_signature_correct(message, secret, signature):
    digest = hmac.new(secret, msg=message, digestmod=hashlib.sha1).hexdigest()
    return hmac.compare_digest(digest, signature.lower())


def _prepare_response(body):
    author_id = json.loads(body)["task"]["author"]["id"]
    employer_tech_company_id, employer_tech_sup_id = get_id_employer()
    if author_id in employer_tech_company_id:
        for employer in employer_tech_sup_id:
            if employer['first_name'] == 'Поддержка' and employer['last_name'] == 'Первый':
                worker_id = employer['id']
                break
    else:
        for employer in employer_tech_sup_id:
            if employer['first_name'] == 'Поддержка' and employer['last_name'] == 'Второй':
                worker_id = employer['id']
                break
    return "{{  \"reassign_to\":{{ \"id\":{} }}, \"approval_choice\": \"{}\" }}".format(worker_id, 'approved')


def get_id_employer():
    access_token = os.environ['access_token']
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    r = requests.get(
        'https://api.pyrus.com/v4/members',
        headers=headers
    )
    list_of_members_id = list()
    list_of_members_tech = list()
    for item in r.json()['members']:
        list_of_members_id.append(item['id'])
        if item['position'] == 'tech':
            list_of_members_tech.append(dict(id=item['id'], first_name=item['first_name'], last_name=item['last_name']))
    return list_of_members_id, list_of_members_tech


if __name__ == "__main__":
    app.run()
