.. flask-auth documentation master file, created by
   sphinx-quickstart on Sun Jul 31 14:51:54 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Flask-Auth
==========
.. module:: flaskext.auth

Flask-Auth is a flask extension that offers database-agnostic (but still 
fairly plug-and-play) role-based user authentication. Sounds impressive, 
right?

Features
--------

* Set of functions to assist in user session management (logging in and out,
  getting the current user, expiring sessions, encrypting passwords, etc).
* Base user class AuthUser that can be used with most ORM's.
* Plug-and-play model for Google App Engine (and a working example for 
  SQLAlchemy and MongoAlchemy).
* Straightforward permission model to differentiate access rights between 
  (groups of) users.

Contents
--------

.. toctree::
   :maxdepth: 2

   quickstart
   api
