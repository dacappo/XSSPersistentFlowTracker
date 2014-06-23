<?php	

	function connectToDatabase($server, $user, $password, $database) {

	    $dsn = 'mysql:dbname=' . $database . ';host=' . $server;

	    try {
	        $dbh = new PDO($dsn, $user, $password);
	    } catch (PDOException $e) {
	        echo 'Connection failed: ' . $e->getMessage();
	        $dbh = false;
	    }

	    return $dbh;
	}

	function initializeDatabase($dbh) {
		$queries = array();

		array_push($queries, $createTableCookieWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS Cookies (`Url` varchar(200), `Key` varchar(200), `Value` varchar(200), `Path` varchar(200), `Expire` varchar(200))'));
		array_push($queries, $createTableSessionWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS SessionStorage (`Url` varchar(200), `Key` varchar(200), `Value` varchar(200))'));
		array_push($queries, $createTableLocalWrite = $dbh->prepare('CREATE TABLE IF NOT EXISTS LocalStorage (`Url` varchar(200), `Key` varchar(200), `Value` varchar(200))'));

		foreach ($queries as $q) {
			if($q->execute()) {
			 	echo "Query ran successfully: <span>" . $q->queryString . "</span><br>";
			} else {
			    echo "Error running query: " . array_pop($q->errorInfo()) . " : <span>" . $q->queryString . "</span><br>";
			}
		}

	}