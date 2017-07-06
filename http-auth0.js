/**
 * Copyright 2013, 2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function(RED) {
	"use strict";
	var bodyParser = require("body-parser");
	var cookieParser = require("cookie-parser");
	var getBody = require('raw-body');
	var cors = require('cors');
	var jsonParser = bodyParser.json();
	var urlencParser = bodyParser.urlencoded({
		extended : true
	});
	var onHeaders = require('on-headers');
	var typer = require('media-typer');
	var isUtf8 = require('is-utf8');

	function rawBodyParser(req, res, next) {
		if (req._body) {
			return next();
		}
		req.body = "";
		req._body = true;

		var isText = true;
		var checkUTF = false;

		if (req.headers['content-type']) {
			var parsedType = typer.parse(req.headers['content-type']);
			if (parsedType.type === "text") {
				isText = true;
			} else if (parsedType.subtype === "xml" || parsedType.suffix === "xml") {
				isText = true;
			} else if (parsedType.type !== "application") {
				isText = false;
			} else if (parsedType.subtype !== "octet-stream") {
				checkUTF = true;
			}
		}

		getBody(req, {
			length : req.headers['content-length'],
			encoding : isText ? "utf8" : null
		}, function(err, buf) {
			if (err) {
				return next(err);
			}
			if (!isText && checkUTF && isUtf8(buf)) {
				buf = buf.toString();
			}

			req.body = buf;
			next();
		});
	}

	var corsSetup = false;

	function createRequestWrapper(node, req) {
		// This misses a bunch of properties (eg headers). Before we use this function
		// need to ensure it captures everything documented by Express and HTTP modules.
		var wrapper = {
			_req : req
		};
		var toWrap = ["param", "get", "is", "acceptsCharset", "acceptsLanguage", "app", "baseUrl", "body", "cookies", "fresh", "hostname", "ip", "ips", "originalUrl", "params", "path", "protocol", "query", "route", "secure", "signedCookies", "stale", "subdomains", "xhr", "socket" // TODO: tidy this up
		];
		toWrap.forEach(function(f) {
			if ( typeof req[f] === "function") {
				wrapper[f] = function() {
					node.warn(RED._("httpin.errors.deprecated-call", {
						method : "msg.req." + f
					}));
					var result = req[f].apply(req, arguments);
					if (result === req) {
						return wrapper;
					} else {
						return result;
					}
				};
			} else {
				wrapper[f] = req[f];
			}
		});

		return wrapper;
	}

	function createResponseWrapper(node, res) {
		var wrapper = {
			_res : res
		};
		var toWrap = ["append", "attachment", "cookie", "clearCookie", "download", "end", "format", "get", "json", "jsonp", "links", "location", "redirect", "render", "send", "sendfile", "sendFile", "sendStatus", "set", "status", "type", "vary"];
		toWrap.forEach(function(f) {
			wrapper[f] = function() {
				node.warn(RED._("httpin.errors.deprecated-call", {
					method : "msg.res." + f
				}));
				var result = res[f].apply(res, arguments);
				if (result === res) {
					return wrapper;
				} else {
					return result;
				}
			};
		});
		return wrapper;
	}

	var corsHandler = function(req, res, next) {
		next();
	};

	if (RED.settings.httpNodeCors) {
		corsHandler = cors(RED.settings.httpNodeCors);
		RED.httpNode.options("*", corsHandler);
	}

	function HTTPAuth0(n) {
		RED.nodes.createNode(this, n);
		this.name = n.name;
		this.role = n.role;
		this.group = n.group;		
		this.auth0 = n.auth0;
		this.cookieMaxAge = Number(n.maxage || 900000);		
		this.Auth0 = RED.nodes.getNode(this.auth0);
		if (RED.settings.httpNodeRoot !== false) {

			if (!n.url) {
				this.warn(RED._("httpin.errors.missing-path"));
				return;
			}
			this.url = n.url;
			this.method = n.method;

			var node = this;

			this.errorHandler = function(err, req, res, next) {
				node.warn(err);
				res.sendStatus(500);
			};

			this.callback = function(req, res) {
				var msgid = RED.util.generateId();
				res._msgid = msgid;
				if (node.method.match(/^(post|delete|put|options|patch)$/)) {
					node.send({
						_msgid : msgid,
						req : req,
						res : createResponseWrapper(node, res),
						payload : req.body
					});
				} else if (node.method == "get") {
					node.send({
						_msgid : msgid,
						req : req,
						res : createResponseWrapper(node, res),
						payload : req.query
					});
				} else {
					node.send({
						_msgid : msgid,
						req : req,
						res : createResponseWrapper(node, res)
					});
				}
			};

			function parseBearerToken(req) {
				var auth;
				if (!req.headers || !( auth = req.headers.authorization)) {
					return null;
				}
				var parts = auth.split(' ');
				if (2 > parts.length)
					return null;
				var schema = parts.shift().toLowerCase();
				var token = parts.join(' ');
				if ('bearer' != schema)
					return null;
				return token;
			}

			var httpMiddleware = function(req, res, next) {
				var request = require('request');
				var jwt = require('jsonwebtoken');
				var jwtToken = req.cookies['id_token'] || parseBearerToken(req);
				var tokenProviderUrl = node.Auth0.getTokenAddress();
				var auth0TokenSecret = process.env.AUTH0_CLIENT_SECRET || node.Auth0.getTokenSecret();
				
				if (!req.cookies['id_token'] && jwtToken) {
					node.log("httpMiddleware: SET COOKIE " + jwtToken.substring(0, 10));
					if (jwtToken === "null") {
						res.clearCookie('id_token');
					} else {
						res.cookie('id_token', jwtToken, { maxAge: node.cookieMaxAge, httpOnly: true });	
					}
				}
				
				function requestTokenInfo(req, res, next, maxAge) {
					node.log("httpMiddleware:" + tokenProviderUrl);
					var options = {
						uri : tokenProviderUrl,
						method : 'POST',
						json : {
							id_token : jwtToken
						}
					};
					request(options, function(error, response, body) {
						if (!error && response.statusCode == 200) {
							req.tokeninfo = body || { user_id: "auth0|anonymous" };
							req.tokeninfo.authorized = true;
							req.tokeninfo.email = req.tokeninfo.email || req.tokeninfo.user_id.replace('|', '@');
							if (node.role && req.tokeninfo && req.tokeninfo.roles && req.tokeninfo.roles.indexOf(node.role) == -1) {								
								req.tokeninfo.authorized = false;
							}
							if (node.group && req.tokeninfo && req.tokeninfo.groups && req.tokeninfo.groups.indexOf(node.group) == -1) {
								req.tokeninfo.authorized = false;
							}							
							if (req.tokeninfo.authorized) {
								if (!req.cookies['email']) {
									res.cookie('email', req.tokeninfo.email, { maxAge: maxAge || parseInt(node.cookieMaxAge) || 90000000, httpOnly: true });
									res.cookie('roles', req.tokeninfo.roles, { maxAge: maxAge || parseInt(node.cookieMaxAge) || 90000000, httpOnly: true });
									res.cookie('groups', req.tokeninfo.groups, { maxAge: maxAge || parseInt(node.cookieMaxAge) || 90000000, httpOnly: true });
								}
								next();
							} else {
								res.setHeader('Content-Type', 'application/json');
								res.status(403).end(JSON.stringify({
									required : {
										role : node.role,
										group : node.group,
									},
									message : "Require ROLE:'" + node.role + "' and GROUP:'" + node.group + "' to access the requested resource."
								}));
							}
						} else {
							res.setHeader('Content-Type', 'application/json');
							res.status(401).end(JSON.stringify({
								message : "The JWT token '" + options.json.id_token + "' is invalid."
							}));
						}
					});
				}
				if (auth0TokenSecret) {					
					jwt.verify(jwtToken, new Buffer(auth0TokenSecret, 'base64'), function(tokenError, decoded) {
						if (!tokenError) {							
							node.log("httpMiddleware:" + decoded.aud);
							if (!req.cookies['email']) {
								tokenProviderUrl = decoded.iss + "tokeninfo";
								requestTokenInfo(req, res, next, parseInt(decoded.exp*1000 - new Date().getTime()));
							} else {
								req.tokeninfo = {
									user_id: decoded.sub,
									email: req.cookies['email'],
									roles: req.cookies['roles'],
									groups: req.cookies['groups'],
									client_id: decoded.aud,
									user_info: decoded.iss + "tokeninfo",
									jwt_token: jwtToken
								};
								next();
							}
						} else {
							node.log("httpMiddleware:" + tokenError);
							res.setHeader('Content-Type', 'application/json');
							res.status(401).end(JSON.stringify({
								message : tokenError
							}));
						}
					});
				} else {
					tokenProviderUrl = node.Auth0.getTokenAddress();
					requestTokenInfo(req, res, next);
				}
			};

			if (RED.settings.httpNodeMiddleware) {
				if ( typeof RED.settings.httpNodeMiddleware === "function") {
					httpMiddleware = RED.settings.httpNodeMiddleware;
				}
			}

			var metricsHandler = function(req, res, next) {
				next();
			};

			if (this.metric()) {
				metricsHandler = function(req, res, next) {
					var startAt = process.hrtime();
					onHeaders(res, function() {
						if (res._msgid) {
							var diff = process.hrtime(startAt);
							var ms = diff[0] * 1e3 + diff[1] * 1e-6;
							var metricResponseTime = ms.toFixed(3);
							var metricContentLength = res._headers["content-length"];
							//assuming that _id has been set for res._metrics in HttpOut node!
							node.metric("response.time.millis", {
								_msgid : res._msgid
							}, metricResponseTime);
							node.metric("response.content-length.bytes", {
								_msgid : res._msgid
							}, metricContentLength);
						}
					});
					next();
				};
			}

			if (this.method == "get") {
				RED.httpNode.get(this.url, cookieParser(), httpMiddleware, corsHandler, metricsHandler, this.callback, this.errorHandler);
			} else if (this.method == "post") {
				RED.httpNode.post(this.url, cookieParser(), httpMiddleware, corsHandler, metricsHandler, jsonParser, urlencParser, rawBodyParser, this.callback, this.errorHandler);
			} else if (this.method == "put") {
				RED.httpNode.put(this.url, cookieParser(), httpMiddleware, corsHandler, metricsHandler, jsonParser, urlencParser, rawBodyParser, this.callback, this.errorHandler);
			} else if (this.method == "patch") {
				RED.httpNode.patch(this.url, cookieParser(), httpMiddleware, corsHandler, metricsHandler, jsonParser, urlencParser, rawBodyParser, this.callback, this.errorHandler);
			} else if (this.method == "delete") {
				RED.httpNode.delete(this.url, cookieParser(), httpMiddleware, corsHandler, metricsHandler, jsonParser, urlencParser, rawBodyParser, this.callback, this.errorHandler);
			}

			this.on("close", function() {
				var node = this;
				RED.httpNode._router.stack.forEach(function(route, i, routes) {
					if (route.route && route.route.path === node.url && route.route.methods[node.method]) {
						routes.splice(i, 1);
					}
				});
			});
		} else {
			this.warn(RED._("httpin.errors.not-created"));
		}
	}


	RED.nodes.registerType("http-auth0", HTTPAuth0);

	function Auth0ServerSetup(n) {
		RED.nodes.createNode(this, n);
		this.connected = false;
		this.connecting = false;
		this.usecount = 0;
		// Config node state
		this.name = n.name;
		this.address = n.address;
		this.secret = n.secret;

		var node = this;
		this.register = function() {
			node.usecount += 1;
		};

		this.deregister = function() {
			node.usecount -= 1;
			if (node.usecount == 0) {
			}
		};
		this.getTokenAddress = function() {
			return node.address;
		};
		this.getTokenSecret = function() {
			return node.secret;
		};

		this.on('close', function(closecomplete) {
			if (this.connected) {
				this.on('disconnected', function() {
					closecomplete();
				});
				node.queue.close().then(function() {
					node.log(RED._('closed'));
				});
			} else {
				closecomplete();
			}
		});
	}


	RED.nodes.registerType("auth0-server", Auth0ServerSetup);
};
