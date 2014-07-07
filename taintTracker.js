var taintTracker = {};

(function (namespace) {
	"use strict";
	/*
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
	} */

	function reportFlow(flow) {
		window.postMessage({"sender" : "FROM_TRACKER", "flow" : flow}, "*");
	}
	
	/* Function to check detected flows */
	namespace.handleFlow = function(flow) {
		reportFlow(flow);
	};
	
}(taintTracker));

/* Define function that is called by the taint browser to hand over flows */
var ___DOMXSSFinderReport = function (sink, data, taintArray, details, url) {
	"use strict";

	taintTracker.handleFlow({
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