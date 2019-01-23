import json
import os
import string


from flask import Flask, redirect, request, Response
import dnsknife


from . import registrar
from . import config

app = Flask(__name__)

config.load('/etc/gandi/rrr.yaml')
socks = config.get('socks5_proxy')
if socks:
    dnsknife.set_socks5_server(socks)

reg = registrar.Registrar()

class AppException(Exception):
    code=500
    def __init__(self, e):
        self.message = {'status': '%s occurred' % str(e)}


class DomainNotFound(AppException):
    message={'status': 'domain not found'}
    def __init__(self, domain):
        message={'status': 'domain %s not found' % domain}
    code=404


class Challenge(AppException):
    code=401
    def __init__(self, challenge):
        self.message = {'challenge': challenge}

def JR(w, status=200):
    def stringify(value):
        if isinstance(value, list):
            return [str(v) for v in value]
        return str(value)

    w = dict((k, stringify(v)) for k,v in w.items())
    return Response(json.dumps(w), status=status,
            mimetype='application/json')

@app.errorhandler(AppException)
def appException(exc):
    return JR({'status': 'error', 'text': exc.message}, exc.code)

def check_creds(user, password):
    for u, p in config.get('post_credentials', {}).items():
        if u == user and p == password:
            return True
    return False

def check_auth():
    auth = request.authorization
    if not auth or not check_creds(auth.username, auth.password):
        return Response('Please authenticate', 401,
                        {'WWW-Authenticate': 'Basic realm="initial"'})

def check_domain(domain):
    if not reg.has_domain(domain):
        raise DomainNotFound(domain)

def check_challenge(domain):
    c = dnsknife.Checker(domain, direct=True)
    secret = config.get('challenge_secret')

    if not c.has_challenge(secret, name="_delegate"):
        raise Challenge(c.challenge(secret))


@app.route("/ping")
def ping():
    return Response("pong")


def key_ids(list_of_keys):
    return [dnsknife.dnssec.key_id(x) for x in list_of_keys]

def _check_dnskeys(domain):
    check_domain(domain)
    c = dnsknife.Checker(domain, direct=True)

    errors = []

    try:
        cds = list(set(c.with_query_strategy(
            dnsknife.QueryStrategyAll).cdnskey()))
    #except dnsknife.exceptions.DeleteDS:
    # We shall see later what to do
    #    return ['DELETE']
    except dnsknife.exceptions.Error as e:
        cds = []
        errors.append(str(e))

    try:
        keys = list(set(c.DNSKEY()))
    except (dnsknife.exceptions.Error, dnsknife.exceptions.NoAnswer) as e:
        keys = []
        errors.append(str(e))

    try:
        parent_ds = list(set(c.at_parent().DS()))
    except (dnsknife.exceptions.Error, dnsknife.exceptions.NoAnswer) as e:
        parent_ds = []
        errors.append(str(e))

    return {'parent': parent_ds, # what DS are at the parent
               'child': keys,
               'cds': cds,
               'errors': errors}

@app.route("/domains/<domain>/cds", methods=['GET'])
def check_dnskeys(domain):
    return JR(_check_dnskeys(domain))

@app.route("/domains/<domain>/cds", methods=['POST', 'DELETE', 'PUT'])
def set_dnskeys(domain):
    try:
        data = _check_dnskeys(domain)
    except dnsknife.exceptions.DeleteDS:
        if request.method == 'DELETE':
            return JR({'status': 'deleted', 'rel': reg.set_keys(domain, [])})

    if request.method == 'POST':
        keys = data['cds'] or data['child']
    else:
        keys = data['cds']

    ret = 'noaction'
    if keys:
        ret = reg.set_keys(domain, keys)

    return JR({'status': 'success', 'rel': ret})

@app.route("/domains/<domain>/tokens", methods=['GET', 'POST'])
def new_token(domain):
    r = check_domain(domain)
    if r:
        return r

    secret = config.get('challenge_secret')
    challenge = dnsknife.Checker(domain).challenge(secret)

    return Response('_delegate IN TXT "{}"'.format(challenge), status=200)
