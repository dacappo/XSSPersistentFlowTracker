(function() {
	"use strict";

	function handleResult(result) {
		alert(result);
	}

	function messageBackground(flow) {
		chrome.runtime.sendMessage(flow, handleResult);
	}

	/* Listen for messages from page */
	window.addEventListener("message", function(event) {
		/* Only own window as source allowed */
		if (event.source !== window) {
			return;
		}

		/* Only messages from the page and not the content script */
		if (event.data.type && (event.data.type === "FROM_PAGE")) {
			messageBackground(event.data.flow);
		}
	});

	/* Create the script element */
	var script = document.createElement("script");
	script.setAttribute("type","text/javascript");

	/* get script that is lateron inlcuded into the page */
	var xhr = new XMLHttpRequest();
	var src = chrome.extension.getURL("wrapper.js");
	xhr.open("GET", src, false);
	xhr.send();

	/* Set the script code */
	script.text = xhr.responseText;

	/* Write the script tag into the DOM */
	document.documentElement.insertBefore(script, document.documentElement.firstChild);
}());