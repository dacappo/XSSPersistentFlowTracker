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
			logDatabase ("Query ran successfully: " . $traceCookie->queryString);
		} else {
			logDatabase ("Error running query: " . array_pop($traceCookie->errorInfo()) . " : " . $traceCookie->queryString);
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
			logDatabase ("Query ran successfully: " . $traceSession->queryString);
		} else {
			logDatabase ("Error running query: " . array_pop($traceSession->errorInfo()) . " : " . $traceSession->queryString);
		}
		
	}

	function traceLocalStorage($dbh) {
		$traceLocal = $dbh->prepare('INSERT INTO LocalStorage VALUES(:url, :data, :taint, :key, :value)');
		$traceLocal->bindParam(':url', $_POST["url"]);
		$traceLocal->bindParam(':data', $_POST["data"]);
		$traceLocal->bindParam(':taint', $_POST["taintArray"]);
		$traceLocal->bindParam(':key', $_POST["key"]);
		$traceLocal->bindParam(':value', $_POST["value"]);

		if($traceLocal->execute()) {
			logDatabase ("Query ran successfully: " . $traceLocal->queryString);
		} else {
			logDatabase ("Error running query: " . array_pop($traceLocal->errorInfo()) . " : " . $traceLocal->queryString);
		}		
	}

	function traceFirstOrderFlow($dbh) {
		$traceFirOrderFlow = $dbh->prepare('INSERT INTO FirstOrderFlows VALUES(:sink, :origin, :url, :script, :data, :taint, :key, :value)');
		$traceFirOrderFlow->bindParam(':sink', $_POST["sink"]);
		$traceFirOrderFlow->bindParam(':url', $_POST["url"]);
		$traceFirOrderFlow->bindParam(':origin', $_POST["origin"]);
		$traceFirOrderFlow->bindParam(':script', $_POST["script"]);
		$traceFirOrderFlow->bindParam(':data', $_POST["data"]);
		$traceFirOrderFlow->bindParam(':taint', $_POST["taintArray"]);
		$traceFirOrderFlow->bindParam(':key', $_POST["key"]);
		$traceFirOrderFlow->bindParam(':value', $_POST["value"]);

		if($traceFirOrderFlow->execute()) {
			logDatabase ("Query ran successfully: " . $traceFirOrderFlow->queryString . "");
		} else {
			logDatabase ("Error running query: " . array_pop($traceFirOrderFlow->errorInfo()) . " : " . $traceFirOrderFlow->queryString );
		}
	}

	function traceSecondOrderFlow($dbh) {
		$traceSecOrderFlow = $dbh->prepare('INSERT INTO SecondOrderFlows VALUES(:sink, :origin, :url, :script, :data, :taint)');
		$traceSecOrderFlow->bindParam(':sink', $_POST["sink"]);
		$traceSecOrderFlow->bindParam(':url', $_POST["url"]);
		$traceSecOrderFlow->bindParam(':origin', $_POST["origin"]);
		$traceSecOrderFlow->bindParam(':script', $_POST["script"]);
		$traceSecOrderFlow->bindParam(':data', $_POST["data"]);
		$traceSecOrderFlow->bindParam(':taint', $_POST["taintArray"]);

		if($traceSecOrderFlow->execute()) {
			logDatabase ("Query ran successfully: " . $traceSecOrderFlow->queryString . "");
		} else {
			logDatabase ("Error running query: " . array_pop($traceSecOrderFlow->errorInfo()) . " : " . $traceSecOrderFlow->queryString );
		}
	}

	function writeDataSet() {

		$config = json_decode(file_get_contents("../config.json"));
		$db_config = $config->{"database"};

		/* Set up database connection and tables */
		$dbh = connectToDatabase($db_config->{"host"}, $db_config->{"port"} , $db_config->{"user"}, $db_config->{"password"}, $db_config->{"schema"});
		initializeDatabase($dbh);

		if($_POST["sink"] === "14") {
			traceFirstOrderFlow($dbh);
		} else if($_POST["sink"] === "21") {
			traceFirstOrderFlow($dbh);
		} else {
			traceSecondOrderFlow($dbh);
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