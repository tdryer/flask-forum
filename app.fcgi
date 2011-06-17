#!/usr/bin/env python
from flup.server.fcgi import WSGIServer
from app import app

if __name__ == '__main__':
    print "starting app..."
    WSGIServer(app, bindAddress='/tmp/flask-forum.sock').run()
    print "...stopping app"

