chrome.runtime.onMessage.addListener(
	function(flow) {
		reportFlow(flow);
	}
);

function reportFlow(flow, sendResponse) {
	var xhr = new XMLHttpRequest();
	var src = "http://localhost:8000/reportFlow.php";
	var data = "sink=" + flow.sink + "&url=" + flow.url + "&taintArray=" + flow.taintArray + "&data=" + flow.data + "&details=" + flow.details;

	xhr.onreadystatechange = function(sendResponse) {
		if (xhr.readyState == 4 && xhr.status == 200) {
			alert(JSON.stringify(JSON.parse(xhr.responseText)));
		}
	};
	xhr.open("POST", src, true);
	xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	xhr.send(data);
}
