var wrapper = {};

(function (namespace) {

  /* General wrapping function for functions */
  namespace.wrap = function(func, report) {
  
    console.info('The wrapper for ' + func.name + '() is set!');
    
    return function() {
      // Get array of arguments
      var args = Array.prototype.slice.call(arguments);

      // Add add log commands
      report.call(this, location.href, arguments[0], arguments[1]);
      
      // Call the actual function with given arguments
      return func.apply(this, args);
    };
  };



/*** Doing all the cookie stuff ... you know ***/

  /* Object extracting key and value of cookie strings */
  var cookieParser = {

    /* Gets the key of a cookie */ 
    getKey : function(cookieString) {
      return cookieString.substring(0, cookieString.indexOf("="));
    },

    /* Gets the value of a cookie */
    getValue : function(cookieString) {
      return cookieString.substring(cookieString.indexOf("=") + 1, cookieString.indexOf(";"));
    },

    /* Gets the path value of a cookie */
    getPath : function(cookieString) {
      var parts = cookieString.split(';');
      var result = "";

      /* Check for path declaration */
      for (var i=0; parts.length > i; i++) {
        var part = parts[i];
        if (cookieParser.getKeyOfCookieSection(part) === "path") {
          result = cookieParser.getValueOfCookieSection(part);
        }
      }

      return result;
    },

    /* Gets the expire value of a cookie */
    getExpire : function(cookieString) {
      var parts = cookieString.split(';');
      var result = "";

      // Check for expiration declaration
      for (var i=0; parts.length > i; i++) {
        var part = parts[i];
        if (cookieParser.getKeyOfCookieSection(part) === "expires") {
          result = cookieParser.getValueOfCookieSection(part);
        }
      }

      return result;
    },

    /* Gets the key of a key-value pair*/
    getKeyOfCookieSection : function(section) {
      return section.substring(0, section.indexOf('=')).trim();
    },

    /* Gets the value of a key-value pair*/
    getValueOfCookieSection : function(section) {
      return section.substring(section.indexOf('=') + 1, section.length);
    }

  };

  function reportSetCookie(url, key, value) {
  	window.postMessage({"sender" : "FROM_WRAPPER", "dataset" : { "type" : "setCookie", "url" : url, "key" : key, "value" : value }}, "*");
  };

  
 
    
  /* New setter function for cookies */
  function setCookie(input) {

    // Log function call
    reportSetCookie(location.href, cookieParser.getKey(input), cookieParser.getValue(input), cookieParser.getPath(input), cookieParser.getExpire(input));

    // Restore the document.cookie property
    delete document.cookie;

    // Set the cookie
  	document.cookie = input;

    // Redefine the getter and setter for document.cookie
    namespace.wrapCookie();
  };

  /* New getter function for cookies */
  function getCookie() {

    // Log function call
    
    //reportGetCookie(location.href, cookieParser.getKey(input), cookieParser.getValue(input), cookieParser.getPath(input), cookieParser.getExpire(input));

    // Restore the document.cookie property
    delete document.cookie;

    // Cache the resulting cookie value
    var result = document.cookie;

    // Redefine the getter and setter for document.cookie
    namespace.wrapCookie();

    // Return the cookie value
    return result;
  };

  /* Wraps the setter and getter of document.cookie */
  namespace.wrapCookie = function() {
    Object.defineProperty(document, "cookie", { "get" : getCookie, "set" : setCookie});
  };

  
}(wrapper));

/* Wrap sessionStorage setter */
sessionStorage.setItem = wrapper.wrap(sessionStorage.setItem, function(url, key, value) {window.postMessage({"sender" : "FROM_WRAPPER", "dataset" : { "type" : "sessionStorage.setItem", "url" : url, "key" : key, "value" : value}}, "*");});
localStorage.setItem = wrapper.wrap(localStorage.setItem, function(url, key, value) {window.postMessage({"sender" : "FROM_WRAPPER", "dataset" : {"type" : "localStorage.setItem", "url" : url, "key" : key, "value" : value}}, "*");});

/* Define new getter and setter for document.cookie */
wrapper.wrapCookie();