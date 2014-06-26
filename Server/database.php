<?php
	
	/* */
	$logDatabaseQueries = true;

	function logDatabase($message) {
		if ($GLOBALS['logDatabaseQueries']) {
			$file = "log.txt";
			$current = file_get_contents($file);
			file_put_contents($file, $current . $message . "\n");
		}
	}


	function connectToDatabase($server, $user, $password, $database) {

	    $dsn = 'mysql:dbname=' . $database . ';host=' . $server;

	    try {
	        $dbh = new PDO($dsn, $user, $password);
	    } catch (PDOException $e) {
	        logDatabase('Connection failed: ' . $e->getMessage());
	        $dbh = false;
	    }

	    return $dbh;
	}

	/* NOTE: make sure that php5-mysql package is installed for PDO */
	function initializeDatabase($dbh) {
		$queries = array();
		
		/*array_push($queries, $createTableCookieWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS Cookies (`Url` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048), `Path` varchar(200), `Expire` varchar(200))'));
		array_push($queries, $createTableSessionWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS SessionStorage (`Url` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048))'));
		array_push($queries, $createTableLocalWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS LocalStorage (`Url` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048))'));*/
		array_push($queries, $createTableSessionWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS FirstOrderFlows (`Sink` int, `Origin` varchar(2048), `Url` varchar(2048), `Script` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048))'));
		array_push($queries, $createTableSecondOrderFlowWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS SecondOrderFlows (`Sink` int, `Origin` varchar(2048), `Url` varchar(2048), `Script` varchar(2048), `Data` text, `TaintArray` text)'));

		foreach ($queries as $q) {
			if($q->execute()) {
			 	logDatabase("Query ran successfully: " . $q->queryString);
			} else {
			    logDatabase("Error running query: " . array_pop($q->errorInfo()) . " : " . $q->queryString );
			}
		}
	}
