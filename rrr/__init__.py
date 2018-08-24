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


class CDSException(AppException):
    code=400


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
    return Response(json.dumps(w), status=status,
            mimetype='application/json')

@app.errorhandler(AppException)
def appException(exc):
    return JR(exc.message, exc.code)

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

def get_dnskeys(domain, dnssec=True):
    c = dnsknife.Checker(domain, direct=True, dnssec=dnssec)
    try:
        return set(c.cdnskey())
    except dnsknife.exceptions.DeleteDS:
        return []
    except (dnsknife.exceptions.BadCDNSKEY,
            dnsknife.exceptions.NoTrust,
            dnsknife.exceptions.NoAnswer,
            dnsknife.exceptions.NoDNSSEC), e:
        raise CDSException(e)


@app.route("/ping")
def ping():
    return Response("pong")


def key_ids(list_of_keys):
    return [dnsknife.dnssec.key_id(x) for x in list_of_keys]

@app.route("/domains/<domain>/cds", methods=['GET'])
def check_dnskeys(domain):
    check_domain(domain)
    initial = get_dnskeys(domain, False)
    secure = get_dnskeys(domain)
    return JR({'secure_cds': key_ids(secure),
               'initial_cds': key_ids(initial)})

@app.route("/domains/<domain>/cds", methods=['POST', 'DELETE', 'PUT'])
def set_dnskeys(domain):
    check_domain(domain)

    if request.method == 'POST':
        check_auth()
        check_challenge(domain)
        keys = get_dnskeys(domain, False)
    else:
        keys = get_dnskeys(domain)

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
