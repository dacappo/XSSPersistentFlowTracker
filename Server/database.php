<?php
	
	/* */
	$logDatabaseQueries = false;

	function log(message) {
		if (logDatabaseQueries) {
			echo message;
		}
	}


	function connectToDatabase($server, $user, $password, $database) {

	    $dsn = 'mysql:dbname=' . $database . ';host=' . $server;

	    try {
	        $dbh = new PDO($dsn, $user, $password);
	    } catch (PDOException $e) {
	        log 'Connection failed: ' . $e->getMessage();
	        $dbh = false;
	    }

	    return $dbh;
	}

	/* NOTE: make sure that php5-mysql package is installed for PDO */
	function initializeDatabase($dbh) {
		$queries = array();
		
		array_push($queries, $createTableCookieWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS Cookies (`Url` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048) `Value` varchar(2048), `Path` varchar(200), `Expire` varchar(200))'));
		array_push($queries, $createTableSessionWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS SessionStorage (`Url` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048))'));
		array_push($queries, $createTableLocalWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS LocalStorage (`Url` varchar(2048), `Data` text, `TaintArray` text, `Key` varchar(2048), `Value` varchar(2048))'));

		foreach ($queries as $q) {
			if($q->execute()) {
			 	log "Query ran successfully: <span>" . $q->queryString . "</span><br>";
			} else {
			    log "Error running query: " . array_pop($q->errorInfo()) . " : <span>" . $q->queryString . "</span><br>";
			}
		}
	}
