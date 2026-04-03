<?php


$name = $_GET['name'];
echo('Hello ' . $name);

$id = $_POST['id'];
mysql_query("SELECT user FROM users WHERE id = " . $id);


$cmd = $_COOKIE['cmd'];
exec("cat /var/log/apache2/access.log | grep " . $cmd);


$words = split(":", "split:this");
