import yaml

CONF = {
    'challenge_secret': 'fieyoo7ajohche8ahhiequ4ohXue6tuu',
    'api': {
        'url': 'http://localhost:8083/',
        'key': 'somekey'
    },
}

def load(filename):
    with open(filename) as f:
        conf = yaml.load(f)
        if conf:
            CONF.update(conf)

def get(key, default=''):
    d = CONF
    for k in key.split('.'):
        d = d.get(k, {})
    return d or default
