<?php require_once('initialize.php'); ?>
<?php $data_set = select_all_intrusions()?> 
<?php session_start() ?>

<!DOCTYPE html>
<html lang="en">
<head>    
    <title>Intrusion Detection System Home</title>
	<link rel="stylesheet" type="text/css" href="style.css">
    <script type="text/javascript">  
        window.onload = function () {  
        var chart = new CanvasJS.Chart("chartContainer",  
        {  
        title:{  
        text: "Adding dataPoints"    
        },  
        data: [  
            {          
                type: "column",  
                dataPoints: [  
                { y: 71 },  
                { y: 55},  
                { y: 50 },  
                { y: 65 },  
                { y: 95 },  
                { y: 68 },  
                { y: 28 },  
                { y: 34 },  
                { y: 14}  
                ]  
            }  
        ]  
    });  
    chart.render();  
    }  
  </script>  
 <script type="text/javascript"   
src="https://canvasjs.com/assets/script/canvasjs.min.js"></script>
</head>  
	<body>
	<h1 class="header">Intrusion Detection System</h1>
	<h3>Group 1: Patryk Kaiser, Daniel Mackey, Ingrid Melin</h3>

	<div class="topNav" id="topNavMenu">
		<a href="..\index.php">Home</a>
		<a href="..\insert\newI.php">Report An Incident</a>
		<a href="..\admin.php">Admin Control Panel</a>
		</div>
		<?php 
		if(!isset($_SESSION['usersession'])) { 
			redirect_to('login.php');
		}?>
		<p><?php echo "Logged in as: " . $_SESSION['usersession']; ?></p>
			<a href="logout.php">Logout</a>
		<div>
        <div id="chartContainer" style="height: 300px; width: 100%;">  
    </body>
    </html>