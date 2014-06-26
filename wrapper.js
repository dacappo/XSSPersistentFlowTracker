var flowTracker = {};

(function (namespace) {
	"use strict";
	
	var sources = {
		"0"  : "benign",
		"1"  : "location.href",
		"2"  : "location.pathname",
		"3"  : "location.search",
		"4"  : "location.hash",
		"5"  : "document.URL",
		"6"  : "document.documentURI",
		"7"  : "document.baseURI",
		"8"  : "document.Cookie",
		"9"  : "document.referrer",
		"10" : "document.domain",
		"11" : "window.name",
		"12" : "postMessage",
		"13" : "localStorage",
		"14" : "sessionStorage"
	};

	var sinks = {
		"0" : "benign",
		"1" : "eval",
		"2" : "document.write",
		"3" : "innerHTML",
		"4" : "srcdoc style",
		"5" : "script.text",
		"7" : "location",
		"8" : "script.src",
		"9" : "formaction",
		"10" : "src.style",
		"14" : "cookie",
		"15" : "postMessage",
		"16" : "setAttribute(name)",
		"17" : "setAttribute(value)",
		"18" : "setAttribute(both, name)",
		"19" : "setAttribute(both, value)",
		"20" : "storage.setItem(name)",
		"21" : "storage.setItem(value)",
		"22" : "storage.setItem(both, name)",
		"23" : "storage.setItem(both, vlue)"
	};

	function getSink(sink) {
		return sinks[sink];
	}

	function getSource(source) {
		return sources[source];
	}

	function reportFlow(flow) {
		window.postMessage({"type" : "FROM_PAGE", "flow" : flow}, "*");
	}

	function logFirstOrderFlow(flow) {
		reportFlow(flow);
		console.info("First-order-flow written from " + flow.taintArray + " to "  + getSink(flow.sink) + " - " + flow.data);
	}

	function logSecondOrderFlow(flow) {
		reportFlow(flow);
		console.info("Second-order-flow written from " + flow.taintArray + " to "  + getSink(flow.sink) + " - " + flow.data);
	}

	function containsSourceFromURL(taintArray) {
		var i = 0;

		for(i = 0; i < taintArray.length; i++) {
			/* If source from URL */
			if (taintArray[i] > 0 && taintArray[i] < 8) {
				return true;
			}
		}
		return false;
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

	/* Check if input flows into any storage sink */
	function checkFirstOrderFlow(flow) {
		/* setItem of session or local storage */
		if ((flow.sink === 21 || flow.sink === 14) && containsSourceFromURL(flow.taintArray)) {
			logFirstOrderFlow(flow)	;	
		}
	}
	
	/* Check if input in the storage flows into a vulnerable sink */
	function checkSecondOrderFlow(flow) {
		/* setItem of session or local storage */
		if (flow.sink > 0 && flow.sink < 9 && containsSourceFromStorage(flow.taintArray)) {
			logSecondOrderFlow(flow);
		}
	}

	
	/* Function to check detected flows */
	namespace.handleFlow = function(flow) {
		checkFirstOrderFlow(flow);
		checkSecondOrderFlow(flow);
	};
	
}(flowTracker));

/* Define function that is called by the taint browser to hand over flows */
var ___DOMXSSFinderReport = function (sink, data, taintArray, details, url) {
	"use strict";

	flowTracker.handleFlow({
		"sink" : sink,
		"data" : data,
		"taintArray" : taintArray,
		"details" :details,
		"url" : window.location.href,
		"script" : url,
		"origin" : window.location.origin
	});	
};

/* Log that this file was run */
console.log("--- Tracking initialized ---");