A private certificate authority and a server certificate made for the demo's
stand-in HTTPS servers (CN "VPN Works demo server"). They run only inside the
demo's own private network, and run-demo.sh trusts ca.pem for that run alone.
server.key protects nothing outside the demo, and it is public on purpose.
