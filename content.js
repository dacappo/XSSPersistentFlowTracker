(function() {
	"use strict";

	var cookiesSet = [];
	var cookiesGet = [];
	var storageSet = [];
	var storageGet = [];

	function messageBackground(flow) {
		chrome.runtime.sendMessage(flow);
	}

	function containsSourceFromStorage(taintArray) {
		var i = 0;

		for(i = 0; i < taintArray.length; i++) {
			/* If cookie, session or local storage */
			if (taintArray[i] === 8 || taintArray[i] === 13 || taintArray[i] === 14) {
				return true;
			}
		}
		return false;
	}

	function getTaintedPartsFromSecondOrderFlow(flow) {
		var i = 0;
		var result = [];
		var taint = 0;
		var length = 0;

		for(i = 0; i < flow.taintArray.length; i++) {
			/* If cookie, session or local storage */

			if (flow.taintArray[i] === taint) {
				length++;
			} else if(flow.taintArray[i-1] === 8 || flow.taintArray[i-1] === 13 || flow.taintArray[i-1] === 14){
				result.push({"source" : taint, "start" : i - length, "end" : i -1, "value" : flow.data.substring(i-length, i)});

				length = 1;
				taint = flow.taintArray[i];
			}
		}
		
		return result;
	}

	function matchTaintedFlow(flow) {
		
		var i = 0;
		var j = 0;
		var k = 0;
		
		if (flow.sink === 14) {
			/* match cookie first order flows */ /* TODO: refactor that with just a single array */
			for(i = 0; i < cookiesSet.length; i++) {
				if(flow.data.indexOf(cookiesSet[i].value) >= 0) {					
					flow.key = cookiesSet[i].key;
					flow.value = cookiesSet[i].value;
					flow.type = cookiesSet[i].type;
				} 
			}
		} else if (flow.sink === 21) {
			/* match storage first order flows */ 
			for(i = 0; i < storageSet.length; i++) {
				if(flow.data.indexOf(storageSet[i].value) >= 0) {
					flow.key = storageSet[i].key;
					flow.value = storageSet[i].value;
					flow.type = storageSet[i].type;
				} 
			}
		} else if (containsSourceFromStorage(flow.taintArray)) {
			/* match second order flows */
			var parts = getTaintedPartsFromSecondOrderFlow(flow);
			flow.sources = [];

			for (i = 0; i < parts.length; i++) {
				if (parts[i].source === 8) {
					// Cookie
					for (j = 0; j < cookiesGet.length; j++) {
						for (k = 0; k < cookiesGet[j].pairs.length; k++) {
							if(cookiesGet[j].pairs[k].value.indexOf(parts[i].value) >= 0) {
								flow.sources.push({"source" : cookiesGet[j].type, "key" : cookiesGet[j].pairs[k].key, "value" : cookiesGet[j].pairs[k].value});
							}
						}
						
					}
				} else if (parts[i].source === 13 || parts[i].source === 14) {
					for (j = 0; j < storageGet.length; j++) {
						if(storageGet[j].value.indexOf(parts[i].value) >= 0) {
							flow.sources.push({"source" : storageGet[j].type, "key" : storageGet[j].key, "value" : storageGet[j].value});
						} 
					}
				}
			}
		}


		messageBackground(flow);
	}

	function logFunctionCall(dataset) {
		if (dataset.type === "setCookie") {
			cookiesSet.push(dataset);
		} else if (dataset.type === "getCookie") {
			cookiesGet.push(dataset);
		} else if (dataset.type === "sessionStorage.setItem") {
			storageSet.push(dataset);
		} else if (dataset.type === "localstorage.setItem") {
			storageSet.push(dataset);
		} else if (dataset.type === "sessionstorage.getItem") {
			storageGet.push(dataset);
		} else if (dataset.type === "localStorage.getItem") {
			storageGet.push(dataset);
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
			matchTaintedFlow(event.data.flow);
		} else if(event.data.sender && (event.data.sender === "FROM_WRAPPER")) {
			logFunctionCall(event.data.dataset);
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