<?php
	
	require "database.php";

	function traceCookie($dbh) {
		$traceCookie = $dbh->prepare('INSERT INTO Cookies VALUES(:url, :key, :value, :path, :expire)');
		$traceCookie->bindParam(':url', $_POST["url"]);
		$traceCookie->bindParam(':key', $_POST["key"]);
		$traceCookie->bindParam(':value', $_POST["value"]);
		$traceCookie->bindParam(':path', $_POST["path"]);
		$traceCookie->bindParam(':expire', $_POST["expire"]);

		if($traceCookie->execute()) {
			echo "Query ran successfully: <span>" . $traceCookie->queryString . "</span><br>";
		} else {
			echo "Error running query: " . array_pop($traceCookie->errorInfo()) . " : <span>" . $traceCookie->queryString . "</span><br>";
		}
	}

	function traceSessionStorage($dbh) {
		$traceSession = $dbh->prepare('INSERT INTO SessionStorage VALUES(:url, :key, :value)');
		$traceSession->bindParam(':url', $_POST["url"]);
		$traceSession->bindParam(':key', $_POST["key"]);
		$traceSession->bindParam(':value', $_POST["value"]);

		if($traceSession->execute()) {
			echo "Query ran successfully: <span>" . $traceSession->queryString . "</span><br>";
		} else {
			echo "Error running query: " . array_pop($traceSession->errorInfo()) . " : <span>" . $traceSession->queryString . "</span><br>";
		}
		
	}

	function traceLocalStorage($dbh) {
		$traceLocal = $dbh->prepare('INSERT INTO LocalStorage VALUES(:url, :key, :value)');
		$traceLocal->bindParam(':url', $_POST["url"]);
		$traceLocal->bindParam(':key', $_POST["key"]);
		$traceLocal->bindParam(':value', $_POST["value"]);

		if($traceLocal->execute()) {
			echo "Query ran successfully: <span>" . $traceLocal->queryString . "</span><br>";
		} else {
			echo "Error running query: " . array_pop($traceLocal->errorInfo()) . " : <span>" . $traceLocal->queryString . "</span><br>";
		}		
	}

	function writeDataSet() {

		/* Set up database connection and tables */
		$dbh = connectToDatabase("localhost","tracer","tracer","tracing");
		initializeDatabase($dbh);
		
		if($_POST["sink"] == 0) {
			traceCookie($dbh);
		} else if($_POST["sink"] == 1) {
			traceSessionStorage($dbh);
		} else if($_POST["sink"] == 2) {
			traceLocalStorage($dbh);
		}		
	}

	/* Allow access on script - cross origin domain */
	header('Access-Control-Allow-Origin: *');

	/* Write to database */
	writeDataSet();