<?php 

	function sanitizeSql($sql) {
		global $db;

		return mysqli_real_escape_string($db, $sql);
	}

	function index_select($id, $table) {
		global $db;

		$statement = "SELECT * FROM " . sanitizeSql($table) . " ";
		$statement .= "WHERE " . $table . "_id = '" . $id . "';";
		$result = mysqli_query($db, $statement);
		confirm_result_set($result);
		return $result;
	}
	
	function select_all_intrusions() {
		global $db;

		$statement = "SELECT * FROM intrusion ";
		$statement .= "ORDER BY intrusion_id ASC";
		$result = mysqli_query($db, $statement);
		confirm_result_set($result);
		return $result;
	}

	function select_intrusion_details($id) {
		global $db;

		$statement = "SELECT * FROM detail ";
		$statement .= "WHERE intrusion_id = '" . $id . "';";
		$result = mysqli_query($db, $statement);
		confirm_result_set($result);
		return $result;
	}

	function select_user($username, $password) {
		global $db;

		$statement = "SELECT * FROM users ";
		$statement .= "WHERE username = '" . $username . "' AND password = '" . $password . "' LIMIT 1";
		$result = mysqli_query($db, $statement);
		confirm_result_set($result);
		return $result;
	}

	function insert_user($username, $password) {
		global $db;

		$sql = "INSERT INTO users(username, password) VALUES(";
		$sql.= "'" . h(sanitizeSql($username)) . "',";
		$sql .= "'" . h(sanitizeSql($password)) . "');";
		$result = mysqli_query($db, $sql);
		if($result) {
			return true;

		} else {
			echo mysqli_error($db);
			db_disconnect($db);
			exit;
		}
	}

?>