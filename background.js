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

	function alertVulnerability(firstOrderFlow, SecondOrderFlow) {
		alert("Set red icon");
		chrome.browserAction.setIcon({path: "logo_alert.png"});
	}

	function checkForVulnerability(secondOrderFlow){
		var i, j;

		for (i = 0; i < firstOrderFlows.length; i++) {
			if (firstOrderFlows[i].origin === secondOrderFlow.origin) {
				for (j = 0; j < secondOrderFlow.sources.length; j++) {
					if(secondOrderFlow.sources[j].key === firstOrderFlows[i].key) {
						alertVulnerability(firstOrderFlows[i], secondOrderFlow);
					}
				}
			} else {
				return;
			}

		}		
	}

	chrome.runtime.onMessage.addListener(
		function(flow) {
			// Log to server
			if (settings.reportToServer) {
				reportFlow(flow);
			}

			// Log locally
			if (flow.type === "firstOrder") {
				firstOrderFlows.push(flow);
			} else if (flow.type === "secondOrder") {
				secondOrderFlows.push(flow);
				checkForVulnerability(flow);
			}

		}
	);
}());
