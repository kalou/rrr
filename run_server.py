from rrr import app, config
import dnsknife

config.load('/etc/gandi/rrr.yaml')
socks = config.get('socks_proxy')
if socks:
    dnsknife.set_socks5_server(socks)
app.run(debug=True, use_reloader=True, host='0.0.0.0')
