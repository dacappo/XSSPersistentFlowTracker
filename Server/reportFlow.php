<?php
	
	require "database.php";

	function traceCookie($dbh) {
		$traceCookie = $dbh->prepare('INSERT INTO Cookies VALUES(:url, :data, :taint, :key, :value, :path, :expire)');
		$traceCookie->bindParam(':url', $_POST["url"]);
		$traceCookie->bindParam(':data', $_POST["data"]);
		$traceCookie->bindParam(':taint', $_POST["taintArray"]);
		$traceCookie->bindParam(':key', $_POST["key"]);
		$traceCookie->bindParam(':value', $_POST["value"]);
		$traceCookie->bindParam(':path', $_POST["path"]);
		$traceCookie->bindParam(':expire', $_POST["expire"]);

		if($traceCookie->execute()) {
			log "Query ran successfully: <span>" . $traceCookie->queryString . "</span><br>";
		} else {
			log "Error running query: " . array_pop($traceCookie->errorInfo()) . " : <span>" . $traceCookie->queryString . "</span><br>";
		}
	}

	function traceSessionStorage($dbh) {
		$traceSession = $dbh->prepare('INSERT INTO SessionStorage VALUES(:url, :data, :taint, :key, :value)');
		$traceSession->bindParam(':url', $_POST["url"]);
		$traceSession->bindParam(':data', $_POST["data"]);
		$traceSession->bindParam(':taint', $_POST["taintArray"]);
		$traceSession->bindParam(':key', $_POST["key"]);
		$traceSession->bindParam(':value', $_POST["value"]);

		if($traceSession->execute()) {
			log "Query ran successfully: <span>" . $traceSession->queryString . "</span><br>";
		} else {
			log "Error running query: " . array_pop($traceSession->errorInfo()) . " : <span>" . $traceSession->queryString . "</span><br>";
		}
		
	}

	function traceLocalStorage($dbh) {
		$traceLocal = $dbh->prepare('INSERT INTO LocalStorage VALUES(:url, :data, :taint :key, :value)');
		$traceLocal->bindParam(':url', $_POST["url"]);
		$traceLocal->bindParam(':data', $_POST["data"]);
		$traceLocal->bindParam(':taint', $_POST["taintArray"]);
		$traceLocal->bindParam(':key', $_POST["key"]);
		$traceLocal->bindParam(':value', $_POST["value"]);

		if($traceLocal->execute()) {
			log "Query ran successfully: <span>" . $traceLocal->queryString . "</span><br>";
		} else {
			log "Error running query: " . array_pop($traceLocal->errorInfo()) . " : <span>" . $traceLocal->queryString . "</span><br>";
		}		
	}

	function writeDataSet() {

		/* Set up database connection and tables */
		$dbh = connectToDatabase("localhost","root","root","XSS");
		initializeDatabase($dbh);
		
		if($_POST["sink"] === "14") {
			traceCookie($dbh);
		} else if($_POST["sink"] === "21") {
			traceSessionStorage($dbh);
		} else if($_POST["sink"] === "2") {
			traceLocalStorage($dbh);
		}
	}

	/* Write to database */
	writeDataSet();

	/* Allow access on script - cross origin domain */
	header('Access-Control-Allow-Origin', '*');
	header('Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS');
	header('Content-type: application/json');
	header('Cache-Control: no-cahe, must-revalidate');

	$result = ['sink'=>$_POST["sink"]];

	echo (json_encode($result));