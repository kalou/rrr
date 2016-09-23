import yaml

CONF = {
    'challenge_secret': 'fieyoo7ajohche8ahhiequ4ohXue6tuu',
    'registrar_backend': '/some/endpoint',
    'registrar_secret': '/some/endpoint',
}

def load(filename):
    with open(filename) as f:
        conf = yaml.load(f)
        if conf:
            CONF.update(conf)

def get(key):
    d = CONF
    for k in key.split('.'):
        d = d.get(k, {})
    return d
