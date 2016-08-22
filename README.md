# node-red-contrib-http-auth0
Yet another [http in] with auth0 authentication provider to verify every incoming requests containing oauth2_token

[![npm version](https://badge.fury.io/js/node-red-contrib-http-auth0.svg)](https://badge.fury.io/js/node-red-contrib-http-auth0) ![codeship](https://codeship.com/projects/dfcc3910-2420-0134-486b-76d3d72b136a/status?branch=master)

The first thing to do you need to register an account at https://auth0.com/ then go to **Clients** menu and CREATE CLIENT. Remember your *Domain* value to use in the next step.

**Import the test flow into your node-red after installing the http-auth0 node module:**

```
[{"id":"b176ac6b.c1adb","type":"http-auth0","z":"bda2c5b8.dfd998","name":"","role":"","group":"","url":"/test","method":"get","auth0":"2cd14f9f.247e8","x":200,"y":180,"wires":[["b1520a2.4062ff8"]]},{"id":"b1520a2.4062ff8","type":"debug","z":"bda2c5b8.dfd998","name":"","active":true,"console":"false","complete":"false","x":420,"y":180,"wires":[]},{"id":"2cd14f9f.247e8","type":"auth0-server","z":"bda2c5b8.dfd998","name":"Your Auth0 Account","address":"https://yourdomain.auth0.com/tokeninfo"}]
```

**Edit the http-auth0 node with your *Domain* value above in the Account setting panel.**

- By default, it checks for the valid auth0's token and pass the request to the downstream node.
- Request is authorized if the **role** value is set to the auth0 user's role value. Usually setup by https://manage.auth0.com/#/rules
- Request is authorized if the **group** value is set to the auth0 user's group value. Usually setup by installing the **Auth0 Authorization 1.4 extension**

**Try to get your auth0's id_token from your auth0 application and pass it into the Authorization Header**

Currently it supports only **Bearer** token which is taken from **id_token** parameter.

```javascript
curl -i http://127.0.0.1:1880/test -H "Authorization: Bearer {{auth0-id-token}}"
```
