(function() {
	"use strict";

	var cookiesSet = [];
	var cookiesGet = [];
	var storageSet = [];
	var storageGet = [];

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
			cookiesSet.push(dataset);
		} else if (dataset.method === "getCookie") {
			cookiesGet.push(dataset);
		} else if (dataset.method === "sessionStorage.setItem") {
			storageSet.push(dataset);
		} else if (dataset.method === "localStorage.setItem") {
			storageSet.push(dataset);
		} else if (dataset.method === "sessionStorage.getItem") {
			storageGet.push(dataset);
		} else if (dataset.method === "localStorage.getItem") {
			storageGet.push(dataset);
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

	function handleFirstOrderStorageFlow(flow) {
		var i;
		// Loop through traced storage set calles
		for (i = 0; i < storageSet.length; i++) {
			// Match taint information with wrapper information

			if (flow.data.indexOf(storageSet[i].value) >= 0) {
				flow.key = storageSet[i].key;
				flow.value = storageSet[i].value;
				flow.method = storageSet[i].method; 
			}
		}

		traceFirstOrderFlow(flow);
	}

	function handleFirstOrderCookieFlow(flow) {
		var i;

		// Loop through traced cookie set calles
		for (i = 0; i < cookiesSet.length; i++) {
			// Match taint information with wrapper information
			if (flow.data.indexOf(cookiesSet[i].value) >= 0) {
				flow.key = cookiesSet[i].key;
				flow.value = cookiesSet[i].value;
				flow.method = cookiesSet[i].method; 
			}
		}

		traceFirstOrderFlow(flow);
	}

	function matchFirstOrderFlow(flow) {

		if (flow.sink === 21) {
			handleFirstOrderStorageFlow(flow);
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

		for (i = 0; i < storageGet.length; i++) {
			if(storageGet[i].value.indexOf(taintPart.value) >= 0) {
				return {"method" : storageGet[i].method, "key" : storageGet[i].key, "value" : storageGet[i].value, "source" : taintPart.source, "start" : taintPart.start, "end" : taintPart.end, "part" : taintPart.value};
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