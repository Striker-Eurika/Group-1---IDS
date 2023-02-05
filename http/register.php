<?php require_once('initialize.php'); ?>

<!DOCTYPE html>
<html lang="en">

<head>
	<title>Register</title>
	<link rel="stylesheet" type="text/css" href="style.css">
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

	<h1>Register New User</h1>
	<p>Complete the form below to register as a new user</p>
	<p>Click <a href="/login.php">here</a> to login </p>
	<form action="create_user.php" method="post">
		<dl>
			<dt>Username: </dt>
			<dd><input type="text" name="username" value=""></dd>
		</dl>
		<dl>
			<dt>Password: </dt>
			<dd><input type="password" name="password" value=""></dd>
		</dl>
		<div id="operations">
			<input type="submit" value="Register">
		</div>
	</form>
</body>

</html>