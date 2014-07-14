(function() {

	var firstOrderFlows = [];
	var secondOrderFlows = [];

	

	var xhr = new XMLHttpRequest();
	var src = chrome.extension.getURL("config.json");
	xhr.open("GET", src, false);
	xhr.send();

	var settings = JSON.parse(xhr.responseText);

	function serializeForRequest(obj) {
		return "data=" + encodeURIComponent(JSON.stringify(obj));
	}

	function reportFlow(flow) {
		var xhr = new XMLHttpRequest();
		var src = "http://" + settings.server.host + ":" + settings.server.port + "/reportFlow.php";
		var data = 	serializeForRequest(flow);

		xhr.open("POST", src, true);
		xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
		xhr.send(data);
	}

	function alertVulnerability(firstOrderFlow, secondOrderFlow) {
		alert("Vulnerability detected: " + JSON.stringify(firstOrderFlow) + "||" + JSON.stringify(secondOrderFlow));
	}

	function equals(sinkMethod, sourceMethod) {
		var result;

		if ((sinkMethod === "setCookie" && sourceMethod === "getCookie") ||
			(sinkMethod === "localStorage.setItem" && sourceMethod === "localStorage.getItem") ||
			(sinkMethod === "sessionStorage.setItem" && sourceMethod === "sessionStorage.getItem") ) {
			result = true;
		} else {
			result = false;
		}

		return result;
	}

	function checkForVulnerability(secondOrderFlow){
		var i, j;

		for (i = 0; i < firstOrderFlows.length; i++) {
			if (firstOrderFlows[i].origin === secondOrderFlow.origin) {
				for (j = 0; j < secondOrderFlow.sources.length; j++) {
					if(secondOrderFlow.sources[j].key === firstOrderFlows[i].key &&
						equals(firstOrderFlows[i].method, secondOrderFlow.sources[j].method)) {
						alertVulnerability(firstOrderFlows[i], secondOrderFlow);
					}
				}
			}
		}		
	}

	function logFirstOrderFlow(firstOrderFlow) {
		var i;

		for (i = 0; i < firstOrderFlows.length; i++) {
			if (firstOrderFlow.origin === firstOrderFlows[i].origin &&
				firstOrderFlow.method === firstOrderFlows[i].method &&
				firstOrderFlow.key === firstOrderFlows[i].key) {

				firstOrderFlows[i] = firstOrderFlow;
				return;
			}
		}

		firstOrderFlows.push(firstOrderFlow);
	}

	chrome.runtime.onMessage.addListener(
		function(flow) {
			// Log to server
			if (settings.reportToServer) {
				reportFlow(flow);
			}

			// Log locally
			if (flow.type === "firstOrder") {
				logFirstOrderFlow(flow);
			} else if (flow.type === "secondOrder") {
				secondOrderFlows.push(flow);
				checkForVulnerability(flow);
			}

		}
	);
}());
