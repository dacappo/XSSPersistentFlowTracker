var script = document.createElement("script");
script.setAttribute("type","text/javascript");

var xhr = new XMLHttpRequest();
var src = chrome.extension.getURL("wrapper.js");
xhr.open("GET", src, false);
xhr.send();

script.text = xhr.responseText;

document.documentElement.insertBefore(script, document.documentElement.firstChild);