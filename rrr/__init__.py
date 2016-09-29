import os
import json


from flask import Flask, redirect, Response
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


def check_domain(domain):
    if not reg.has_domain(domain):
        return JR({'status': 'domain_not_found'}, 404)

def check_challenge(domain):
    c = dnsknife.Checker(domain, direct=True)
    secret = config.get('challenge_secret')

    if not c.has_challenge(secret):
        return JR({'challenge': c.challenge(secret)}, 403)

def apply_dnskey(domain, dnssec=False):
    c = dnsknife.Checker(domain, direct=True, dnssec=dnssec)
    try:
        new_keys = c.cdnskey()
        op = reg.set_keys(domain, new_keys)
        return op
    except dnsknife.exceptions.DeleteDS:
        op = reg.set_keys(domain, [])
        return op
    except (dnsknife.exceptions.BadCDNSKEY,
            dnsknife.exceptions.NoTrust), e:
        print e.__class__
        return JR({'status': str(e)}, 400)
    except Exception, e:
        print e.__class__
        return JR({'status': str(e)}, 500)


@app.route("/ping")
def ping():
    return Response("pong")


@app.route("/domains/<domain>/cds", methods=['POST'])
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

@app.route("/domains/<domain>/tokens", methods=['POST'])
def set_token(domain):
    r = check_domain(domain)
    if r:
        return r

    secret = config.get('challenge_secret')
    challenge = dnsknife.Checker(domain).challenge(secret)

    return Response('@ IN TXT "{}"'.format(challenge), status=201)
