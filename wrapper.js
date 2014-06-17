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

	var logFirstOrderFlow = function(flow) {


	};

	var containsSourceFromURL = function(taintArray) {
		var i = 0;

		for(i = 0; i < taintArray.length; i++) {
			if (taintArray[i] > 0 && taintArray[i] < 8) {
				return true;
			}
		}
		return false;
	};


	var getSink = function(sink) {
		return sinks[sink];
	};

	var getSource = function(source) {
		return sources[source];
	};

	/* Check if input flows into any storage sink */
	var checkFirstOrderFlow = function(flow) {
		/* setItem of session or local storage */
		if (flow.sink === 21 && containsSourceFromURL(flow.taintArray)) {
			logFirstOrderFlow(flow);
			console.info("Tainted cookie written from " + flow.taintArray + " to "  + getSink(flow.sink) + " - " + flow.data);
		
		/* set cookie */
		} else if (flow.sink === 14 && containsSourceFromURL(flow.taintArray)) {
			logFirstOrderFlow(flow);
			console.log(flow);
			console.info("Tainted cookie written from " + flow.taintArray + " to "  + getSink(flow.sink) + " - " + flow.data);
		}
	};
	
	/* Check if input in the storage flows into a vulnerable sink */
	var checkSecondOrderFlow = function(flow) {

	};

	/* Function to check detected flows */
	namespace.handleFlow = function(flow) {
		checkFirstOrderFlow(flow);
		checkSecondOrderFlow(flow);
	};

}(flowTracker));

var ___DOMXSSFinderReport = function (sink, data, taintArray, details, url) {
	
	flowTracker.handleFlow({
		"sink" : sink,
		"data" : data,
		"taintArray" : taintArray,
		"details" :details,
		"url" : url
	});	
};

console.log("Tracking initialized");