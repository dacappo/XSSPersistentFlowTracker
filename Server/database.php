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


	function connectToDatabase($server, $port, $user, $password, $database) {

	    $dsn = 'mysql:dbname=' . $database . ';host=' . $server . ";port=" . $port;

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
		
		array_push($queries, $createTableSessionWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS FirstOrderFlows (`ID` int NOT NULL AUTO_INCREMENT, `Sink` int, `Method` varchar(100), `Origin` varchar(2048), `Url` varchar(2048), `Script` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048), PRIMARY KEY (ID))'));
		array_push($queries, $createTableSecondOrderFlowWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS SecondOrderFlows (`ID` int NOT NULL AUTO_INCREMENT, `Sink` int, `Origin` varchar(2048), `Url` varchar(2048), `Script` varchar(2048), `Data` text, `TaintArray` text, PRIMARY KEY (ID))'));

		foreach ($queries as $q) {
			if($q->execute()) {
			 	logDatabase("Query ran successfully: " . $q->queryString);
			} else {
			    logDatabase("Error running query: " . array_pop($q->errorInfo()) . " : " . $q->queryString );
			}
		}
	}
