<?php require_once('initialize.php'); ?>
<?php $data_set = select_all_intrusions() ?>
<?php session_start() ?>

<!DOCTYPE html>
<html lang="en">

<head>
	<title>Intrusion Detection System Home</title>
	<link rel="stylesheet" type="text/css" href="style.css">
</head>

<body>
	<?php
	if (!isset($_SESSION['usersession'])) {
		redirect_to('login.php');
	} ?>
	<h1 class="header">Intrusion Detection System</h1>
	<h3>Group 1: Patryk Kaiser, Daniel Mackey, Ingrid Melin</h3>
	<?php echo "Logged in as: " . $_SESSION['usersession']; ?>

	<div class="topNav" id="topNavMenu">
		<a href="..\index.php">Anomaly List</a>
		<a href="logout.php">Logout</a>
	</div>

	<div>
		<table class="incidents">
			<tr>
				<th>Anomaly ID</th>
				<th>Suspected Attack Type</th>
				<th>Time of Detection</th>
				<th>&nbsp;</th>
			</tr>

			<?php while ($intrusion = mysqli_fetch_assoc($data_set)) { ?>
				<?php $attack = mysqli_fetch_assoc(index_select($intrusion['attack_id'], 'attack')); ?>
				<tr>
					<td>
						<?php echo h(sanitizeSql($intrusion['intrusion_id'])); ?>
					</td>
					<td>
						<?php echo h(sanitizeSql($attack['attack_type'])); ?>
					</td>
					<td>
						<?php echo h(sanitizeSql($intrusion['time_of_detection'])); ?>
					</td>
					<td><a class="action" href="<?php echo '/view.php?id=' . $intrusion['intrusion_id']; ?>">View Anomaly Details</a></td>
				</tr>
			<?php } ?>
		</table>

		<?php
		mysqli_free_result($data_set);
		?>

		<footer>
			<p>Group 1: Patryk Kaiser, Daniel Mackey, Ingrid Melin</p>
		</footer>
	</div>
</body>

</html>