This is a simple example and quick-start template for micro web sites and services in Flask.

Quick start for development:
```
pip3 install flask

FLASK_APP=template.py FLASK_ENV=development flask run
```

For production, use Apache with mod_wsgi ([example configuration](apache.conf)), nginx with uWSGI, or any other WSGI compatible server.

