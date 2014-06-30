chrome.runtime.onMessage.addListener(
	function(flow) {
		reportFlow(flow);
	}
);

function serializeForRequest(obj) {
	var result = "";

	for (var prop in obj) {
		if (obj.hasOwnProperty(prop)) {
			result += prop + "=" + obj[prop] + "&";
		}
	}
	
	return "data=" + JSON.stringify(obj);
}

function reportFlow(flow) {
	var xhr = new XMLHttpRequest();
	var src = "http://localhost:8000/reportFlow.php";
	var data = 	serializeForRequest(flow);

	xhr.onreadystatechange = function() {
		if (xhr.readyState == 4 && xhr.status == 200) {
			//sendResponse(JSON.stringify(JSON.parse(xhr.responseText)));
		}
	};
	xhr.open("POST", src, true);
	xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	xhr.send(data);
}
