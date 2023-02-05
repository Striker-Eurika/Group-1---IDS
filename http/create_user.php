<?php

	require_once('initialize.php');

	if(is_post_request()) {
		$username = $_POST['username'] ?? '';
		$password = $_POST['password'] ?? '';

		$result = insert_user($username, $password);
		redirect_to('index.php');
	} else {
		redirect_to('index.php');
	}

?>
