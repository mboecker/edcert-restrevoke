[![Build Status](https://travis-ci.org/zombiemuffin/edcert-restrevoke.svg?branch=master)](https://travis-ci.org/zombiemuffin/edcert-restrevoke)

This is an implementation for a REST-style revoke infrastructure. This contains
both the code of the crate "edcert-restrevoke", which is the client
implementation (fully rust) and also a sample implementation of a server (found in
revoke-server), which is a simple PHP script querying a MySQL database.

# Design

The architecture is as follows: You can have multiple "clients", which all
connect to one (or more) revoke-server. These can query if a certain public
key has been revoked, or not. The server will eg. query a database for public
keys known to be revoked and send an appropriate response.

A public key and therefore a certificate will be revoked, if the private key
has been disclosed, or the authenticity can't be guaranteed for other reason
