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


def JR(w, status=200):
    return Response(json.dumps(w), status=status,
                    mimetype="application/json")

def check_auth(user, password):
    for u, p in config.get('post_credentials', {}).items():
        if u == user and p == password:
            return True
    return False

def requires_auth(f):
    def decorate(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response('Please authenticate', 401,
                            {'WWW-Authenticate': 'Basic realm="initial"'})
        return f(*args, **kwargs)
    return decorate

def check_domain(domain):
    if not reg.has_domain(domain):
        return JR({'status': 'domain_not_found'}, 404)

def check_challenge(domain):
    c = dnsknife.Checker(domain, direct=True)
    secret = config.get('challenge_secret')

    if not c.has_challenge(secret, name="_delegate"):
        return JR({'challenge': c.challenge(secret), }, 403

def apply_dnskey(domain, dnssec=False):
    c = dnsknife.Checker(domain, direct=True, dnssec=dnssec)
    try:
        new_keys = set(c.cdnskey())
        op = reg.set_keys(domain, new_keys)
        return op
    except dnsknife.exceptions.DeleteDS:
        op = reg.set_keys(domain, [])
        return op
    except (dnsknife.exceptions.BadCDNSKEY,
            dnsknife.exceptions.NoTrust,
            dnsknife.exceptions.NoAnswer), e:
        print e.__class__
        return JR({'status': str(e)}, 400)
    except Exception, e:
        print e.__class__
        return JR({'status': str(e)}, 500)


@app.route("/ping")
def ping():
    return Response("pong")


@app.route("/domains/<domain>/cds", methods=['POST'])
@requires_auth
def new_dnskeys(domain):
    r = check_domain(domain) or check_challenge(domain)
    if r:
        return r

    ret = apply_dnskey(domain)
    if isinstance(ret, Response):
        return ret

    return JR({'status': 'success', 'rel': ret}, 201)

@app.route("/domains/<domain>/cds", methods=['DELETE', 'PUT'])
def set_dnskeys(domain):
    r = check_domain(domain)
    if r:
        return r

    ret = apply_dnskey(domain, dnssec=True)
    if isinstance(ret, Response):
        return ret

    return JR({'status': 'success', 'rel': ret})

@app.route("/domains/<domain>/tokens", methods=['GET', 'POST'])
def new_token(domain):
    r = check_domain(domain)
    if r:
        return r

    secret = config.get('challenge_secret')
    challenge = dnsknife.Checker(domain).challenge(secret)

    return Response('_delegate IN TXT "{}"'.format(challenge), status=200)
