/* Scrobble my Jam
 *
 * Bookmarklet JavaScript for scrobbling http://thisismyjam.com to
 * Last.FM. If it doesn't scrobble, it doesn't count.
 * 
 * (c) 2011 Ben Ward (@benward, http://benward.me)
 *
 * BSD License
 *
 * Get an API key from http://last.fm/api
 *
 */
(function () {

  var settings = {
        username: ""
      , password: ""
      , logging: false
      , key: ""
      , secret: ""
      };

  !function(settings) {

    var username = settings.username
      , password = settings.password
      , logging = settings.logging 
      , apikey = settings.key
      , apisecret = settings.secret
      , lastPlaying
      , lastScrobbled
      , lastPosition
      , scrobbles = []
      , exports = this
      , md5
      , lfm
      , lsess
      , cti
      , sti;

    /* MD5 For Last.FM API */
    !function (exports) {
      /*
       * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
       * Digest Algorithm, as defined in RFC 1321.
       * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
       * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
       * Distributed under the BSD License
       * See http://pajhome.org.uk/crypt/md5 for more info.
       */

      /*
       * Configurable variables. You may need to tweak these to be compatible with
       * the server-side, but the defaults work in most cases.
       */
      var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
      var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
      var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

      /*
       * These are the functions you'll usually want to call
       * They take string arguments and return either hex or base-64 encoded strings
       */
      function md5(s){ return hex_md5(s); }
      function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * chrsz));}

      /*
       * Perform a simple self-test to see if the VM is working
       */
      function md5_vm_test()
      {
        return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
      }

      /*
       * Calculate the MD5 of an array of little-endian words, and a bit length
       */
      function core_md5(x, len)
      {
        /* append padding */
        x[len >> 5] |= 0x80 << ((len) % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        var a =  1732584193;
        var b = -271733879;
        var c = -1732584194;
        var d =  271733878;

        for(var i = 0; i < x.length; i += 16)
        {
          var olda = a;
          var oldb = b;
          var oldc = c;
          var oldd = d;

          a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
          d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
          c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
          b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
          a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
          d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
          c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
          b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
          a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
          d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
          c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
          b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
          a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
          d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
          c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
          b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

          a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
          d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
          c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
          b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
          a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
          d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
          c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
          b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
          a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
          d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
          c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
          b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
          a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
          d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
          c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
          b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

          a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
          d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
          c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
          b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
          a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
          d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
          c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
          b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
          a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
          d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
          c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
          b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
          a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
          d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
          c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
          b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

          a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
          d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
          c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
          b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
          a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
          d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
          c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
          b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
          a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
          d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
          c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
          b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
          a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
          d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
          c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
          b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

          a = safe_add(a, olda);
          b = safe_add(b, oldb);
          c = safe_add(c, oldc);
          d = safe_add(d, oldd);
        }
        return Array(a, b, c, d);

      }

      /*
       * These functions implement the four basic operations the algorithm uses.
       */
      function md5_cmn(q, a, b, x, s, t)
      {
        return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
      }
      function md5_ff(a, b, c, d, x, s, t)
      {
        return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
      }
      function md5_gg(a, b, c, d, x, s, t)
      {
        return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
      }
      function md5_hh(a, b, c, d, x, s, t)
      {
        return md5_cmn(b ^ c ^ d, a, b, x, s, t);
      }
      function md5_ii(a, b, c, d, x, s, t)
      {
        return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
      }

      /*
       * Calculate the HMAC-MD5, of a key and some data
       */
      function core_hmac_md5(key, data)
      {
        var bkey = str2binl(key);
        if(bkey.length > 16) bkey = core_md5(bkey, key.length * chrsz);

        var ipad = Array(16), opad = Array(16);
        for(var i = 0; i < 16; i++)
        {
          ipad[i] = bkey[i] ^ 0x36363636;
          opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        var hash = core_md5(ipad.concat(str2binl(data)), 512 + data.length * chrsz);
        return core_md5(opad.concat(hash), 512 + 128);
      }

      /*
       * Add integers, wrapping at 2^32. This uses 16-bit operations internally
       * to work around bugs in some JS interpreters.
       */
      function safe_add(x, y)
      {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF);
        var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
      }

      /*
       * Bitwise rotate a 32-bit number to the left.
       */
      function bit_rol(num, cnt)
      {
        return (num << cnt) | (num >>> (32 - cnt));
      }

      /*
       * Convert a string to an array of little-endian words
       * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
       */
      function str2binl(str)
      {
        var bin = Array();
        var mask = (1 << chrsz) - 1;
        for(var i = 0; i < str.length * chrsz; i += chrsz)
          bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (i%32);
        return bin;
      }

      /*
       * Convert an array of little-endian words to a hex string.
       */
      function binl2hex(binarray)
      {
        var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
        var str = "";
        for(var i = 0; i < binarray.length * 4; i++)
        {
          str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
                 hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
        }
        return str;
      }

      exports.md5 = md5;

    }(exports);

    /* Last.FM API wrapper */
    !function (exports) {
      /*
       * Copyright (c) 2008-2010, Felix Bruns <felixbruns@web.de>
       */

      function LastFM(options) {
      	/* Set default values for required options. */
      	var apiKey    = options.apiKey    || '';
      	var apiSecret = options.apiSecret || '';
      	var apiUrl    = options.apiUrl    || 'http://ws.audioscrobbler.com/2.0/';
      	var cache     = options.cache     || undefined;

      	/* Set API key. */
      	this.setApiKey = function(_apiKey){
      		apiKey = _apiKey;
      	};

      	/* Set API key. */
      	this.setApiSecret = function(_apiSecret){
      		apiSecret = _apiSecret;
      	};

      	/* Set API URL. */
      	this.setApiUrl = function(_apiUrl){
      		apiUrl = _apiUrl;
      	};

      	/* Set cache. */
      	this.setCache = function(_cache){
      		cache = _cache;
      	};

      	/* Set the JSONP callback identifier counter. This is used to ensure the callbacks are unique */
      	var jsonpCounter = 0;

      	/* Internal call (POST, GET). */
      	var internalCall = function(params, callbacks, requestMethod){
      		/* Cross-domain POST request (doesn't return any data, always successful). */
      		if(requestMethod == 'POST'){
      			/* Create iframe element to post data. */
      			var html   = document.getElementsByTagName('html')[0];
      			var iframe = document.createElement('iframe');
      			var doc;

      			/* Set iframe attributes. */
      			iframe.width        = 1;
      			iframe.height       = 1;
      			iframe.style.border = 'none';
      			iframe.onload       = function(){
      				/* Remove iframe element. */
      				//html.removeChild(iframe);

      				/* Call user callback. */
      				if(typeof(callbacks.success) != 'undefined'){
      					callbacks.success();
      				}
      			};

      			/* Append iframe. */
      			html.appendChild(iframe);

      			/* Get iframe document. */
      			if(typeof(iframe.contentWindow) != 'undefined'){
      				doc = iframe.contentWindow.document;
      			}
      			else if(typeof(iframe.contentDocument.document) != 'undefined'){
      				doc = iframe.contentDocument.document.document;
      			}
      			else{
      				doc = iframe.contentDocument.document;
      			}

      			/* Open iframe document and write a form. */
      			doc.open();
      			doc.clear();
      			doc.write('<form method="post" action="' + apiUrl + '" id="form">');

      			/* Write POST parameters as input fields. */
      			for(var param in params){
      				doc.write('<input type="text" name="' + param + '" value="' + params[param] + '">');
      			}

      			/* Write automatic form submission code. */
      			doc.write('</form>');
      			doc.write('<script type="application/x-javascript">');
      			doc.write('document.getElementById("form").submit();');
      			doc.write('</script>');

      			/* Close iframe document. */
      			doc.close();
      		}
      		/* Cross-domain GET request (JSONP). */
      		else{
      			/* Get JSONP callback name. */
      			var jsonp = 'jsonp' + new Date().getTime() + jsonpCounter;

      			/* Update the unique JSONP callback counter */
      			jsonpCounter += 1;

      			/* Calculate cache hash. */
      			var hash = auth.getApiSignature(params);

      			/* Check cache. */
      			if(typeof(cache) != 'undefined' && cache.contains(hash) && !cache.isExpired(hash)){
      				if(typeof(callbacks.success) != 'undefined'){
      					callbacks.success(cache.load(hash));
      				}

      				return;
      			}

      			/* Set callback name and response format. */
      			params.callback = jsonp;
      			params.format   = 'json';

      			/* Create JSONP callback function. */
      			window[jsonp] = function(data){
      				/* Is a cache available?. */
      				if(typeof(cache) != 'undefined'){
      					var expiration = cache.getExpirationTime(params);

      					if(expiration > 0){
      						cache.store(hash, data, expiration);
      					}
      				}

      				/* Call user callback. */
      				if(typeof(data.error) != 'undefined'){
      					if(typeof(callbacks.error) != 'undefined'){
      						callbacks.error(data.error, data.message);
      					}
      				}
      				else if(typeof(callbacks.success) != 'undefined'){
      					callbacks.success(data);
      				}

      				/* Garbage collect. */
      				window[jsonp] = undefined;

      				try{
      					delete window[jsonp];
      				}
      				catch(e){
      					/* Nothing. */
      				}

      				/* Remove script element. */
      				if(head){
      					head.removeChild(script);
      				}
      			};

      			/* Create script element to load JSON data. */
      			var head   = document.getElementsByTagName("head")[0];
      			var script = document.createElement("script");

      			/* Build parameter string. */
      			var array = [];

      			for(var param in params){
      				array.push(encodeURIComponent(param) + "=" + encodeURIComponent(params[param]));
      			}

      			/* Set script source. */
      			script.src = apiUrl + '?' + array.join('&').replace(/%20/g, '+');

      			/* Append script element. */
      			head.appendChild(script);
      		}
      	};

      	/* Normal method call. */
      	var call = function(method, params, callbacks, requestMethod){
      		/* Set default values. */
      		params        = params        || {};
      		callbacks     = callbacks     || {};
      		requestMethod = requestMethod || 'GET';

      		/* Add parameters. */
      		params.method  = method;
      		params.api_key = apiKey;

      		/* Call method. */
      		internalCall(params, callbacks, requestMethod);
      	};

      	/* Signed method call. */
      	var signedCall = function(method, params, session, callbacks, requestMethod){
      		/* Set default values. */
      		params        = params        || {};
      		callbacks     = callbacks     || {};
      		requestMethod = requestMethod || 'GET';

      		/* Add parameters. */
      		params.method  = method;
      		params.api_key = apiKey;

      		/* Add session key. */
      		if(session && typeof(session.key) != 'undefined'){
      			params.sk = session.key;
      		}

      		/* Get API signature. */
      		params.api_sig = auth.getApiSignature(params);

      		/* Call method. */
      		internalCall(params, callbacks, requestMethod);
      	};

      	/* Auth methods. */
      	this.auth = {
      		getMobileSession : function(params, callbacks){
      			/* Set new params object with authToken. */
      			params = {
      				username  : params.username,
      				authToken : md5(params.username + md5(params.password))
      			};

      			signedCall('auth.getMobileSession', params, null, callbacks);
      		},

      		getSession : function(params, callbacks){
      			signedCall('auth.getSession', params, null, callbacks);
      		},

      		getToken : function(callbacks){
      			signedCall('auth.getToken', null, null, callbacks);
      		}
      	};

      	/* Track methods. */
      	this.track = {
      		addTags : function(params, session, callbacks){
      			signedCall('track.addTags', params, session, callbacks, 'POST');
      		},

      		getInfo : function(params, callbacks){
      			call('track.getInfo', params, callbacks);
      		},

      		love : function(params, session, callbacks){
      			signedCall('track.love', params, session, callbacks, 'POST');
      		},

      		scrobble : function(params, session, callbacks){
      			/* Flatten an array of multiple tracks into an object with "array notation". */
      			if(params.constructor.toString().indexOf("Array") != -1){
      				var p = {};

      				for(i in params){
      					for(j in params[i]){
      						p[j + '[' + i + ']'] = params[i][j];
      					}
      				}

      				params = p;
      			}

      			signedCall('track.scrobble', params, session, callbacks, 'POST');
      		},

      		unlove : function(params, session, callbacks){
      			signedCall('track.unlove', params, session, callbacks, 'POST');
      		},

      		updateNowPlaying : function(params, session, callbacks){
      			signedCall('track.updateNowPlaying', params, session, callbacks, 'POST');
      		}
      	};

      	/* Private auth methods. */
      	var auth = {
      		getApiSignature : function(params){
      			var keys   = [];
      			var string = '';

      			for(var key in params){
      				keys.push(key);
      			}

      			keys.sort();

      			for(var index in keys){
      				var key = keys[index];

      				string += key + params[key];
      			}

      			string += apiSecret;

      			/* Needs lastfm.api.md5.js. */
      			return md5(string);
      		}
      	};
      }

      exports.lastfm = LastFM;

    }(exports);

    /* make global md5 method for Last.FM module. */
    md5 = this.md5;

    /* Start of our Scrobbling Script stuff. */

    function init () {
      if (!(apikey && apisecret)) {
        alert("You're using a copy of Scrobble my Jam code that doesn't have Last.FM API keys. Get some from http://last.fm/api.");
      }
      else if (!(username && password)) {
        alert("You need to set the `username` and `password` variables.");
      }
      else {
        lfm = new this.lastfm({
          apiKey: apikey
        , apiSecret: apisecret
        });
        lfm.auth.getMobileSession({username: username, password: password}, {
          success: function (data) {
            lsess = data.session;
            cti = setInterval(checkTrack, 5000);
            sci = setInterval(scrobble, 20000);
          }
        , error: function (data, messsage) {
            alert("Last.FM Login Failed. Check your username and password.");
          }
        });
      }
    }

    function log () {
      logging && console && console.log(arguments);
    }

    function nowPlaying (artist, track, duration) {
      log("Now Playing:", artist, track);
      lastPlaying = artist + track;
      lfm.track.updateNowPlaying({ track: track, artist: artist, duration: duration }, lsess, {
        success: function (data) {
            log("Now playing success:", lastPlaying, data);
          }
      , error: function (error, message) {
          log("Now playing failure", message, lastPlaying, error);
        }
      });
    }

    function enqueueScrobble (artist, track) {
      log("Enqueued Scrobble:", artist, track);
      scrobbles.push({artist: artist, track: track, album: null, timestamp: Math.round(Date.now()/1000) });
      lastScrobbled = artist + track;
    }

    function scrobble () {
      log("Processing Scrobble Queue.");
      var s;
      while (s = scrobbles.shift()) {
        log("Scrobbling", s);
        lfm.track.scrobble(s, lsess, {
          success: function (data) {
            log("Scrobble success:", s, data);
          }
        , error: function (e, message) {
            log("Scrobble failure", message, s, e);
            scrobbles.push(s);
          }
        });
      }
    }

    function checkTrack () {
      log("Polling Track");
      var artist = $('#artist-name').text()
        , track = $('#track-title').text()
        , key = artist+track
        , pos = window.player && window.player.currentSound && Math.round(window.player.currentSound.position / 1000)
        , duration = window.player && window.player.currentSound && Math.round(window.player.currentSound.duration / 1000)
        , playing = window.player && window.player.currentSound && !window.player.currentSound.paused;

      if (artist && track && playing) {
    
        // If repeating the same song
        if (key == lastPlaying && pos < lastPosition) {
          lastPosition = 0;
          lastPlaying = lastScrobbled = "";
          log("Detected playing same track twice. Hot jam.");
        }

        // Scrobble if: Song > 30 secs
        // Playback position is > 50%
        // Playback position is > 4 mins
        log("Playback Position", (pos / duration));
        if (duration > 30 && ((pos / duration) > 0.5 || pos > 240)) {
          (key == lastScrobbled) || enqueueScrobble(artist, track);
        }
        if (!lastPlaying != key) {
          (key == lastPlaying) || nowPlaying(artist, track, duration);
        }
      }
      else {
        log("No playback");
      }
    }
  
    init();

  }(settings);
})();