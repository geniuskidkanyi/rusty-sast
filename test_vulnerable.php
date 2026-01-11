<?php
// This is a test file
$user_input = $_GET['cmd'];
exec($user_input); // DANGER

$apiKey = "AKIAIOSFODNN7EXAMPLE"; // AWS Key
$password = "superSecret123";

eval("echo 'hello';");
?>
