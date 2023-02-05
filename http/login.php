<?php
require_once('initialize.php');
session_start();
if (isset($_SESSION['usersession'])) {
	header("Location:index.php");
}

if (isset($_POST['login'])) {
	$username = $_POST['username'];
	$password = $_POST['password'];

	$user_data = select_user($username, $password);
	$user = mysqli_fetch_assoc($user_data);

	if ($username == $user['username'] && $password == $user['password']) {
		$_SESSION['usersession'] = $username;
		redirect_to('index.php');
		//echo("Success");
	} else {
		echo "Invalid Login Details!";
	}
}
?>
<!DOCTYPE html>
<html>

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="stylesheet" type="text/css" href="style.css">
	<title>IDS Login</title>
</head>

<body>
	<h1 class="header">Intrusion Detection System</h1>
	<h3>Group 1: Patryk Kaiser, Daniel Mackey, Ingrid Melin</h3>

	<?php if (isset($_SESSION['usersession'])) { ?>
		<div class="topNav" id="topNavMenu">
			<a href="..\index.php">Anomaly List</a>
			<a href="logout.php">Logout</a>
		</div>
	<?php } ?>

	<h1>Login</h1>
	<p>To access information about alerts and network traffic you must be logged in.</p>
	<p>Click <a href="/register.php">here</a> to register </p>
	<form action="" method="post">
		<dl>
			<dt>Username: </dt>
			<dd><input type="text" name="username" value=""></dd>
		</dl>
		<dl>
			<dt>Password: </dt>
			<dd><input type="password" name="password" value=""></dd>
		</dl>
		<div id="operations">
			<input type="submit" name="login" value="Login">
		</div>
	</form>
</body>

</html>