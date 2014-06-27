(function() {
	"use strict";

	var cookies = [];
	var storage = [];

	function messageBackground(flow) {
		chrome.runtime.sendMessage(flow);
	}

	function matchTaintedFlow(flow) {
		/* match cookie first order flows */ /* TODO: refactor that with just a single array */
		if (flow.sink === 14) {
			for(var i = 0; i < cookies.length; i++) {
				if(flow.data.indexOf(cookies[i].value) >= 0) {
					flow.key = cookies[i].key;
					flow.value = cookies[i].value;
					flow.type = cookies[i].type;
				} 
			}
		} else if (flow.sink === 21) {
			for(i = 0; i < storage.length; i++) {
				if(flow.data.indexOf(storage[i].value) >= 0) {
					flow.key = storage[i].key;
					flow.value = storage[i].value;
					flow.type = storage[i].type;
				} 
			}
		}
		messageBackground(flow);
	}

	function logFunctionCall(dataset) {
		if (dataset.type === "setCookie") {
			cookies.push(dataset);
		} else if (dataset.type === "sessionStorage.setItem") {
			storage.push(dataset);
		} else if (dataset.type === "localStorage.setItem") {
			storage.push(dataset);
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