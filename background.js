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

	chrome.runtime.onMessage.addListener(
		function(flow) {
			// Log to server
			if (settings.reportToServer) {
				reportFlow(flow);
			}

			// Log locally
			if (flow.type === "firstOrder") {
				secondOrderFlows.push(flow);
			} else if (flow.type === "secondOrder") {
				secondOrderFlows.push(flow);
			}

		}
	);
}());
