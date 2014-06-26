chrome.runtime.onMessage.addListener(
	function(flow) {
		reportFlow(flow);
	}
);

function reportFlow(flow) {
	var xhr = new XMLHttpRequest();
	var src = "http://localhost:8000/reportFlow.php";
	var data = 	"sink=" + flow.sink + 
				"&url=" + flow.url + 
				"&origin=" + flow.origin + 
				"&script=" + flow.script + 
				"&taintArray=" + flow.taintArray + 
				"&data=" + flow.data + 
				"&details=" + flow.details +
				"&key=" + flow.key + 
				"&value=" + flow.value;


	xhr.onreadystatechange = function() {
		if (xhr.readyState == 4 && xhr.status == 200) {
			//sendResponse(JSON.stringify(JSON.parse(xhr.responseText)));
		}
	};
	xhr.open("POST", src, true);
	xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	xhr.send(data);
}
