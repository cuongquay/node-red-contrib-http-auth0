# node-red-contrib-http-auth0
Yet another [http in] with auth0 authentication provider to verify every incoming requests containing oauth2_token

[![npm version](https://badge.fury.io/js/node-red-contrib-http-auth0.svg)](https://badge.fury.io/js/node-red-contrib-http-auth0)

https://codeship.com/projects/161369/status?branch=master

Currently it supports only **Bearer** token which is taken from **id_token** parameter.

```javascript
curl -i http://nodered.myapp.com/api/{{test_api}} -H "Authorization: Bearer {{auth0-id-token}}"
```
