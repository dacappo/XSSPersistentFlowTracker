(function() {
	"use strict";

	var cookiesSet = [],
		cookiesGet = [],
		sessionStorageSet = [],
		sessionStorageGet = [],
		localStorageSet = [],
		localStorageGet = [];

	function logCookieSet(dataset) {
		var i = 0;

		for (i = 0; i < cookiesSet.length; i++) {
			if (dataset.key === cookiesSet[i].key) {

				cookiesSet[i] = dataset;
				return;
			}
		}
		cookiesSet.push(dataset);
	}

	function logSessionStorageSet(dataset) {
		var i = 0;

		for (i = 0; i < sessionStorageSet.length; i++) {
			if (dataset.key === sessionStorageSet[i].key) {
				sessionStorageSet[i] = dataset;
				return;
			}
		}

		sessionStorageSet.push(dataset);
	}

	function logLocalStorageSet(dataset) {
		var i = 0;

		for (i = 0; i < localStorageSet.length; i++) {
			if (dataset.key === localStorageSet[i].key) {
				localStorageSet[i] = dataset;
				return;
			}
		}

		localStorageSet.push(dataset);
 	}

	/* Message to background page */
	function messageBackground(flow) {
		chrome.runtime.sendMessage(flow);
	}

	function traceFirstOrderFlow(flow) {
		flow.type = "firstOrder";
		console.info("First order flow detected: " + JSON.stringify(flow));
		messageBackground(flow);
	}

	function traceSecondOrderFlow(flow) {
		flow.type = "secondOrder";
		console.info("Second order flow detected: " + JSON.stringify(flow));
		messageBackground(flow);
	}


	/* Log the wrapped function call information*/
	function handleFunctionCall(dataset) {
		if (dataset.method === "setCookie") {
			logCookieSet(dataset);
		} else if (dataset.method === "getCookie") {
			cookiesGet.push(dataset);
		} else if (dataset.method === "sessionStorage.setItem") {
			logSessionStorageSet(dataset);
		} else if (dataset.method === "localStorage.setItem") {
			logLocalStorageSet(dataset);
		} else if (dataset.method === "sessionStorage.getItem") {
			sessionStorageGet.push(dataset);
		} else if (dataset.method === "localStorage.getItem") {
			localStorageGet.push(dataset);
		}
	}

	function containsSourceFromURL(taintArray) {
		var i;

		for(i = 0; i < taintArray.length; i++) {
			/* If source from URL */
			if (taintArray[i] > 0 && taintArray[i] < 8) {
				return true;
			}
		}
		return false;
	}

	function containsSourceFromStorage(taintArray) {
		/* No taint information from storage! -> logged reading functions are matched
		*  Taint information from URL
		*/ 
		var i;

		for(i = 0; i < taintArray.length; i++) {
			/* If cookie, session or local storage */
			if (taintArray[i] === 8 || taintArray[i] === 13 || taintArray[i] === 14) {
				return true;
			}
		}
		return false;
	}

	/* Check if input flows into any storage sink */
	function checkFirstOrderFlow(flow) {
		var result;

		/* setItem of session, local storage or cookie */
		if ((flow.sink === 21 || flow.sink === 14) && containsSourceFromURL(flow.taintArray)) {
			result = true;
		} else {
			result = false;
		}

		return result;
	}
	
	/* Check if input in the storage flows into a vulnerable sink */
	function checkSecondOrderFlow(flow) {
		var result;

		// Due to inconsistency of the taint values also sources from the URL are allowed -> also accepts normal flows
		if (flow.sink > 0 && flow.sink < 9 && (containsSourceFromStorage(flow.taintArray) || containsSourceFromURL(flow.taintArray))) {
			result = true;
		} else {
			result = false;
		}

		return result;
	}

	function getTaintedPartsFromFlow(flow) {
		
		var result = [];
		var i = 0;
		var taint = 0;
		var length = 0;

		for(i = 0; i <= flow.taintArray.length; i++) {
			
			if (flow.taintArray[i] && flow.taintArray[i] === taint) {
				// Taint stood the same
				length++;
			} else {
				// Taint just changed
				if(flow.taintArray[i-1] && flow.taintArray[i-1] !== 0)  {
					result.push({"source" : taint, "start" : i - length, "end" : i -1, "value" : flow.data.substring(i-length, i)});
				}

				// Reset taint and length
				length = 1;
				taint = flow.taintArray[i];
			}
		}
		
		return result;
	}

	function handleFirstOrderSessionStorageFlow(flow) {
		var i;
		// Loop through traced storage set calles
		for (i = 0; i < sessionStorageSet.length; i++) {
			// Match taint information with wrapper information

			if (flow.data.indexOf(sessionStorageSet[i].value) >= 0) {
				flow.key = sessionStorageSet[i].key;
				flow.value = sessionStorageSet[i].value;
				flow.method = sessionStorageSet[i].method; 
			}
		}

		traceFirstOrderFlow(flow);
	}

	function handleFirstOrderLocalStorageFlow(flow) {
		var i;
		// Loop through traced storage set calles
		for (i = 0; i < localStorageSet.length; i++) {
			// Match taint information with wrapper information

			if (flow.data.indexOf(localStorageSet[i].value) >= 0) {
				flow.key = localStorageSet[i].key;
				flow.value = localStorageSet[i].value;
				flow.method = localStorageSet[i].method; 
			}
		}

		traceFirstOrderFlow(flow);
	}

	function handleFirstOrderCookieFlow(flow) {
		var i;

		// Loop through traced cookie set calles
		for (i = 0; i < cookiesSet.length; i++) {
			// Match taint information with wrapper information
			if (flow.data.split(";")[0].concat(";").indexOf(cookiesSet[i].value) >= 0) {
				flow.key = cookiesSet[i].key;
				flow.value = cookiesSet[i].value;
				flow.method = cookiesSet[i].method;
				flow.expire = cookiesSet[i].expire;
			} 
		}

		if (flow.expire){
			if (Date.parse(flow.expire) > Date.parse(Date())) {
				traceFirstOrderFlow(flow);
			}
		} else if (flow.key){
			traceFirstOrderFlow(flow);
		}

		
	}

	function matchFirstOrderFlow(flow) {

		if (flow.sink === 21 && flow.details[0] === "localStorage") {
			handleFirstOrderLocalStorageFlow(flow);
		} else if (flow.sink === 21 && flow.details[0] === "sessionStorage") {
			handleFirstOrderSessionStorageFlow(flow);
		} else if (flow.sink === 14) {
			handleFirstOrderCookieFlow(flow);
		}
	}

	function matchFlowPartCookie(taintPart) {
		var i, j;

		for (i = 0; i < cookiesGet.length; i++) {
			for (j = 0; j < cookiesGet[i].pairs.length; j++) {
				if(cookiesGet[i].pairs[j].value.indexOf(taintPart.value) >= 0) {
					return {"method" : cookiesGet[i].method, "key" : cookiesGet[i].pairs[j].key, "value" : cookiesGet[i].pairs[j].value, "source" : taintPart.source, "start" : taintPart.start, "end" : taintPart.end, "part" : taintPart.value};
				}
			}
		}

		return null;
	}

	function matchFlowPartStorage(taintPart) {
		var i;

		for (i = 0; i < localStorageGet.length; i++) {
			if(localStorageGet[i].value.indexOf(taintPart.value) >= 0) {
				return {"method" : localStorageGet[i].method, "key" : localStorageGet[i].key, "value" : localStorageGet[i].value, "source" : taintPart.source, "start" : taintPart.start, "end" : taintPart.end, "part" : taintPart.value};
			} 
		}

		for (i = 0; i < sessionStorageGet.length; i++) {
			if(sessionStorageGet[i].value.indexOf(taintPart.value) >= 0) {
				return {"method" : sessionStorageGet[i].method, "key" : sessionStorageGet[i].key, "value" : sessionStorageGet[i].value, "source" : taintPart.source, "start" : taintPart.start, "end" : taintPart.end, "part" : taintPart.value};
			} 
		}

		return null;
	}

	function matchFlowPart(taintPart) {

		var result;

		if (taintPart.source === 8) {
			result = matchFlowPartCookie(taintPart);
		} else {
			result = matchFlowPartStorage(taintPart);
		}

		return result;
	}

	function matchSecondOrderFlow(flow) {

		var taintParts = getTaintedPartsFromFlow(flow);
		var i, result;

		// Extend flow object
		flow.sources = [];

		// Loop through tainted parts
		for (i = 0; i < taintParts.length; i++) {
			result = matchFlowPart(taintParts[i]);
			if (result !== null) {
				flow.sources.push(result);
			}
		}

		// Check if a source exitst originating form any kind of storage
		if (flow.sources.length > 0) {
			traceSecondOrderFlow(flow);
		}
	}

	function handleTaintedFlow(flow) {

		if (checkFirstOrderFlow(flow)) {
			matchFirstOrderFlow(flow);
		} else if (checkSecondOrderFlow(flow)) {
			matchSecondOrderFlow(flow);
		}
	}

	

	/* Listen for messages from page */
	window.addEventListener("message", function(event) {
		/* Only own window as source allowed */
		if (event.source !== window) {
			return;
		}

		/* Only messages from the page and not the content script */
		if (event.data.sender && (event.data.sender === "FROM_TRACKER")) {
			handleTaintedFlow(event.data.flow);
		} else if(event.data.sender && (event.data.sender === "FROM_WRAPPER")) {
			handleFunctionCall(event.data.dataset);
		}
	});

	/* Create the script element */
	var script1 = document.createElement("script");
	script1.setAttribute("type","text/javascript");

	/* get script that is lateron inlcuded into the page */
	var xhr = new XMLHttpRequest();
	var src = chrome.extension.getURL("wrapper.js");
	xhr.open("GET", src, false);
	xhr.send();

	/* Set the script code */
	script1.text = xhr.responseText;

	/* Create the script element */
	var script2 = document.createElement("script");
	script2.setAttribute("type","text/javascript");

	/* get script that is lateron inlcuded into the page */
	xhr = new XMLHttpRequest();
	src = chrome.extension.getURL("taintTracker.js");
	xhr.open("GET", src, false);
	xhr.send();

	/* Set the script code */
	script2.text = xhr.responseText;

	/* Write the script tag into the DOM */
	document.documentElement.insertBefore(script1, document.documentElement.firstChild);
	document.documentElement.insertBefore(script2, document.documentElement.firstChild);
}());