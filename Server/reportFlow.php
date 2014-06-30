<?php
	
	require "database.php";
	$DATA = json_decode($_POST["data"]);

	function stringifyArray($ar) {
		return ("[" . implode(", ", $ar) . "]");
	}

	function traceFirstOrderFlow($dbh) {
		global $DATA;

		$traceFirOrderFlow = $dbh->prepare('INSERT INTO FirstOrderFlows (`Sink`, `Method`, `Origin`, `Url`, `Script`, `Data`, `TaintArray`, `Key`, `Value`) VALUES(:sink, :method, :origin, :url, :script, :data, :taint, :key, :value)');
		$traceFirOrderFlow->bindParam(':sink', $DATA->{"sink"});
		$traceFirOrderFlow->bindParam(':method', $DATA->{"type"});
		$traceFirOrderFlow->bindParam(':url', $DATA->{"url"});
		$traceFirOrderFlow->bindParam(':origin', $DATA->{"origin"});
		$traceFirOrderFlow->bindParam(':script', $DATA->{"script"});
		$traceFirOrderFlow->bindParam(':data', $DATA->{"data"});
		$traceFirOrderFlow->bindParam(':taint', stringifyArray($DATA->{"taintArray"}));
		$traceFirOrderFlow->bindParam(':key', $DATA->{"key"});
		$traceFirOrderFlow->bindParam(':value', $DATA->{"value"});

		if($traceFirOrderFlow->execute()) {
			logDatabase ("Query ran successfully: " . $traceFirOrderFlow->queryString . "");
		} else {
			logDatabase ("Error running query: " . array_pop($traceFirOrderFlow->errorInfo()) . " : " . $traceFirOrderFlow->queryString );
		}
	}

	function traceSecondOrderFlow($dbh) {
		global $DATA;

		$traceSecOrderFlow = $dbh->prepare('INSERT INTO SecondOrderFlows (`Sink`, `Origin`, `Url`, `Script`, `Data`, `TaintArray`) VALUES(:sink, :origin, :url, :script, :data, :taint)');
		$traceSecOrderFlow->bindParam(':sink', $DATA->{"sink"});
		$traceSecOrderFlow->bindParam(':url', $DATA->{"url"});
		$traceSecOrderFlow->bindParam(':origin', $DATA->{"origin"});
		$traceSecOrderFlow->bindParam(':script', $DATA->{"script"});
		$traceSecOrderFlow->bindParam(':data', $DATA->{"data"});
		$traceSecOrderFlow->bindParam(':taint', stringifyArray($DATA->{"taintArray"}));

		if($traceSecOrderFlow->execute()) {
			logDatabase ("Query ran successfully: " . $traceSecOrderFlow->queryString . "");
		} else {
			logDatabase ("Error running query: " . array_pop($traceSecOrderFlow->errorInfo()) . " : " . $traceSecOrderFlow->queryString );
		}
	}


	function writeDataSet() {
		global $DATA;


		$config = json_decode(file_get_contents("../config.json"));
		$db_config = $config->{"database"};

		/* Set up database connection and tables */
		$dbh = connectToDatabase($db_config->{"host"}, $db_config->{"port"} , $db_config->{"user"}, $db_config->{"password"}, $db_config->{"schema"});
		initializeDatabase($dbh);

		if($DATA->{"sink"} === 14 || $DATA->{"sink"} === 21) {
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

	$result = ['sink'=>$DATA->{"sink"}];

	echo (json_encode($result));