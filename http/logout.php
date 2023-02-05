<?php
    require_once('initialize.php');
    
    session_start();

    echo "You Have Logged Out. Goodbye!";

    session_destroy();

    redirect_to('login.php');
?>