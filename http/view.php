<?php require_once('initialize.php'); ?>
<?php $data_set = select_all_intrusions() ?>
<?php session_start() ?>
<?php

// $id = isset($_GET['id']) ? $_GET['id'] : '1';
$id = $_GET['id'] ?? '1'; // PHP > 7.0

$intrusion_detail = mysqli_fetch_assoc(select_intrusion_details($id));
$intrusion = mysqli_fetch_assoc($data_set);
$attack = mysqli_fetch_assoc(index_select($intrusion['attack_id'], 'attack'));

?>
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
	<p>
		<?php echo "Logged in as: " . $_SESSION['usersession']; ?>
	</p>
	<a href="logout.php">Logout</a>
	<h1>Intrusion ID:
		<?php echo h($intrusion_detail['intrusion_id']); ?>
	</h1>

	<dl>
		<dt>Suspected Attack Type</dt>
		<dd>
			<?php echo h(sanitizeSql($attack['attack_type'])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Time of Detection</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion['time_of_detection'])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Source IP</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail['source_ip'])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Destination IP</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail['destination_ip'])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Destination Port</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail['dst_port'])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Duration of Flow in Microseconds</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('flow_duration')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Packets in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('total_fwd_packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Packets in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('total_bwd_packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Size of Packets in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('total_length_of_fwd_packet')])); ?>

		</dd>
	</dl>

	<dl>
		<dt>Total Size of Packets in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('total_length_of_bwd_packet')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Size of Packet in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('fwd_packet_length_max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Size of Packet in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Packet_Length_Min')])); ?>
		</dd>
	</dl>


	<dl>
		<dt>Mean Size of Packet in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Packet_Length_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Size of Packet in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Packet_Length_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Size of Packet in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Packet_Length_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Size of Packet in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Packet_Length_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Size of Packet in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Packet_Length_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Size of Packet in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Packet_Length_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Flow Bytes Per Second</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Flow_Bytes')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Flow Packets Per Second</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Flow_Packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Time Between Two Packets Sent in Flow</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Flow_IAT_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Time Between Two Packets Sent in Flow</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Flow_IAT_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Time Between Two Packets Sent in Flow</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Flow_IAT_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Time Between Two Packets Sent in Flow</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Flow_IAT_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Time Between Two Packets Sent in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_IAT_Total')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Time Between Two Packets Sent in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_IAT_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Time Between Two Packets Sent in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_IAT_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Time Between Two Packets Sent in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_IAT_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Time Between Two Packets Sent in Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_IAT_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Time Between Two Packets Sent in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_IAT_Total')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Time Between Two Packets Sent in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_IAT_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Time Between Two Packets Sent in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_IAT_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Time Between Two Packets Sent in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_IAT_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Time Between Two Packets Sent in Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_IAT_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Times the PSH Flag Was Set in Packets Travelling in the Forward Direction (0 for UDP)</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_PSH_Flags')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Times the PSH Flag Was Set in Packets Travelling in the Backward Direction (0 for UDP)</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_PSH_Flags')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Times the URG Flag Was Set in Packets Travelling in the Forward Direction (0 for UDP)</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_URG_Flags')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Times the URG Flag Was Set in Packets Travelling in the Backward Direction (0 for UDP)</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_URG_Flags')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Bytes Used for Headers in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Header_Length')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Total Bytes Used for Headers in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Header_Length')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Forward Packets Per Second</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Backward Packets Per Second</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Length of a Packet</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Packet_Length_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Length of a Packet</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Packet_Length_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Length of a Packet</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Packet_Length_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Length of a Packet</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Packet_Length_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Variance Length of a Packet</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Packet_Length_Variance')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With FIN</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('FIN_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With SYN</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('SYN_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With RST</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('RST_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With PSH</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('PSH_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With ACK</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('ACK_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With URG</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('URG_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With CWR</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('CWR_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Number of Packets With ECE</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('ECE_Flag_Count')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Download and Upload Ratio</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Down_Up_Ratio')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Size of Packet</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Average_Packet_Size')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Size Observed in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Segment_Size_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Size Observed in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Segment_Size_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Number of Bytes Bulk Rate in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Bytes_Bulk_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Number of Packets Bulk Rate in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Packet_Bulk_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Number of Bulk Rate in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Bulk_Rate_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Number of Bytes Bulk Rate in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Bytes_Bulk_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Number of Packets Bulk Rate in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Packet_Bulk_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Average Number of Bulk Rate in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Bulk_Rate_Avg')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>The Average Number of Packets in a Sub Flow in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Subflow_Fwd_Packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>The Average Number of Bytes in a Sub Flow in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Subflow_Fwd_Bytes')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>The Average Number of Packets in a Sub Flow in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Subflow_Bwd_Packets')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>The Average Number of Bytes in a Sub Flow in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Subflow_Bwd_Bytes')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>The Total Number of Bytes Sent in Initial Window in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('FWD_Init_Win_Bytes')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>The Total Number of Bytes Sent in Initial Window in the Backward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Bwd_Init_Win_Bytes')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Count of Packets With at Least 1 Byte of TCP Data Payload in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Act_Data_Pkts')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Segment Size Observed in the Forward Direction</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Fwd_Seg_Size_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Time a Flow Was Active Before Becoming Idle</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Active_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Time a Flow Was Active Before Becoming Idle</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Active_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Time a Flow Was Active Before Becoming Idle</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Active_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Time a Flow Was Active Before Becoming Idle</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Active_Min')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Mean Time a Flow Was Idle Before Becoming Active</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Idle_Mean')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Standard Deviation Time a Flow Was Idle Before Becoming Active</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Idle_Std')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Maximum Time a Flow Was Idle Before Becoming Active</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Idle_Max')])); ?>
		</dd>
	</dl>

	<dl>
		<dt>Minimum Time a Flow Was Idle Before Becoming Active</dt>
		<dd>
			<?php echo h(sanitizeSql($intrusion_detail[strtolower('Idle_Min')])); ?>
		</dd>
	</dl>

</body>

</html>