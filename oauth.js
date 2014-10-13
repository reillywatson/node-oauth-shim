//
// OAuth
// Author Andrew Dodson
var crypto = require('crypto'),
	url = require('url'),
	querystring = require('querystring');

function merge(a,b){
	var x,r = {};
	if( typeof(a) === 'object' && typeof(b) === 'object' ){
		for(x in a){if(a.hasOwnProperty(x)){
			r[x] = a[x];
			if(x in b){
				r[x] = merge( a[x], b[x]);
			}
		}}
		for(x in b){if(b.hasOwnProperty(x)){
			if(!(x in a)){
				r[x] = b[x];
			}
		}}
	}
	else{
		r = b;
	}
	return r;
}

function hashString(key, str, encoding){
	var hmac = crypto.createHmac("sha1", key);
	hmac.update(str);
	return hmac.digest(encoding);
}

function encode(s){
	return encodeURIComponent(s).replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
}

// Is the parameter considered an OAuth parameter
function isParameterNameAnOAuthParameter(parameter) {
  var m = parameter.match('^oauth_');
  if( m && ( m[0] === "oauth_" ) ) {
    return true;
  }
  else {
    return false;
  }
};

// build the OAuth request authorization header
function buildAuthorizationHeaders(orderedParameters) {
	var oauthParameterSeparator = ",";
  var authHeader="OAuth ";
  if( this._isEcho ) {
    authHeader += 'realm="' + this._realm + '",';
  }

  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if(isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= "" + encode(orderedParameters[i][0])+"=\""+ encode(orderedParameters[i][1])+"\""+ oauthParameterSeparator;
     }
  }

  authHeader= authHeader.substring(0, authHeader.length - oauthParameterSeparator.length);
  return authHeader;
}

module.exports = new (function(){
	this.sign =  function( uri, opts, consumer_secret, token_secret, nonce, method, data ){

		// Damage control
		if(!opts.oauth_consumer_key){
			console.error('OAuth requires opts.oauth_consumer_key');
		}

		// Seperate querystring from path
		var path = uri.replace(/[\?\#].*/,''),
			qs = querystring.parse(url.parse(uri).query);

		// Create OAuth Properties
		var query = {
			oauth_nonce : nonce || parseInt(Math.random()*1e20,10).toString(16),
			oauth_timestamp : nonce || parseInt((new Date()).getTime()/1000,10),
			oauth_signature_method : 'HMAC-SHA1',
			oauth_version : '1.0'
		};

		// Merge opts and querystring
		query = merge( query, opts || {} );
		query = merge( query, qs || {} );
		query = merge( query, data || {} );

		// Sort in order of properties
		var keys = Object.keys(query);
		keys.sort();
		var params = [],
			_queryString = [];

		keys.forEach(function(k){
			if(query[k]){
				params.push( k + "=" + encode(query[k]) );
				if( !data || !(k in data)){
					_queryString.push( k + "=" + encode(query[k]) );
				}
			}
		});

		params = params.join('&');
		_queryString = _queryString.join('&');

		var http = [method || "GET", encode(path).replace(/\+/g," ").replace(/\%7E/g,'~'), encode(params.join('&')).replace(/\+/g," ").replace(/\%7E/g,'~') ];

		// Create oauth_signature
		query.oauth_signature = hashString(
			consumer_secret+'&'+(token_secret||''),
			http.join('&'),
			"base64"
		);

		return {url: (path + '?' + _queryString), signature: encode( query.oauth_signature ) };
	};
});
