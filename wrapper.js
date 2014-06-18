var flowTracker = {};

(function (namespace) {
	
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

	var loggedFlows = [];

	var getSink = function(sink) {
		return sinks[sink];
	};

	var getSource = function(source) {
		return sources[source];
	};

	/* Returns tainted parts of a flow as an object array */
	var getTaintedParts = function(flow) {
		var i, currentTaintLength;
		var taintParts = [];

		/* Iterate over written data */
		for (i = 0; i < flow.taintArray.length; i += currentTaintLength) {
			currentTaintLength = 0;
			/* Check length of part with same source */
			while (i + currentTaintLength < flow.taintArray.length && flow.taintArray[i + currentTaintLength] === flow.taintArray[i]) {
				currentTaintLength++;
			}
			/* Push part with same source as object */
			taintParts.push({"source" : flow.taintArray[i], "data" : flow.data.substring(i, i + currentTaintLength)});
		}

		return taintParts;
	};

	var matchTaintedPartsWithLog = function(taintPart) {
		var i = 0;

		for (i = 0; i < loggedFlows.length; i++) {
			if (loggedFlows[i].data.indexOf(taintPart.data) >= 0) {
				console.info("Second order flow found: Part " + taintPart.data + " from " + getSource(taintPart.source) + " found within " + getSource(loggedFlows[i].taintArray[loggedFlows[i].data.indexOf(taintPart.data)]) + "!");
			}
		}
	};

	var matchFlowWithLog = function(flow) {
		var i = 0;
		var taintPartArray = getTaintedParts(flow);

		for(i = 0; i < taintPartArray.length; i++) {
			matchTaintedPartsWithLog(taintPartArray[i]);
		}
		
	};

	var logFirstOrderFlow = function(flow) {
		loggedFlows.push(flow);
		console.info("Tainted cookie written from " + flow.taintArray + " to "  + getSink(flow.sink) + " - " + flow.data);
	};

	var containsSourceFromURL = function(taintArray) {
		var i = 0;

		for(i = 0; i < taintArray.length; i++) {
			/* If source from URL */
			if (taintArray[i] > 0 && taintArray[i] < 8) {
				return true;
			}
		}
		return false;
	};

	var containsSourceFromStorage = function(taintArray) {
		var i = 0;

		for(i = 0; i < taintArray.length; i++) {
			/* If cookie, session or local storage */
			if (taintArray[i] === 8 || taintArray[i] === 13 || taintArray[i] === 14) {
				return true;
			}
		}
		return false;
	};

	/* Check if input flows into any storage sink */
	var checkFirstOrderFlow = function(flow) {
		/* setItem of session or local storage */
		if (flow.sink === 21 && containsSourceFromURL(flow.taintArray)) {
			logFirstOrderFlow(flow);		
		/* set cookie */
		} else if (flow.sink === 14 && containsSourceFromURL(flow.taintArray)) {
			logFirstOrderFlow(flow);
		}
	};
	
	/* Check if input in the storage flows into a vulnerable sink */
	var checkSecondOrderFlow = function(flow) {
		/* setItem of session or local storage */
		if (flow.sink > 0 && flow.sink < 9 && containsSourceFromStorage(flow.taintArray)) {
			matchFlowWithLog(flow);
			console.info("Second order flow detected!");
		}
	};

	/* Function to check detected flows */
	namespace.handleFlow = function(flow) {
		checkFirstOrderFlow(flow);
		checkSecondOrderFlow(flow);
	};

}(flowTracker));

/* Define function that is called by the taint browser to hand over flows */
var ___DOMXSSFinderReport = function (sink, data, taintArray, details, url) {
	
	flowTracker.handleFlow({
		"sink" : sink,
		"data" : data,
		"taintArray" : taintArray,
		"details" :details,
		"url" : url
	});	
};

/* Log that this file was run */
console.log("Tracking initialized");