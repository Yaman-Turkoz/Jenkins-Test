<?php

$name    = $_GET['name'];
$command = $_GET['cmd'];
$code    = $_GET['code'];
$asd

echo $name;

echo $code;

var_dump($name);


eval($code);

$output = shell_exec($command);

echo $output;

$name = htmlspecialchars($name);
echo $name;

curl_init($name);
curl_init($code);
curl_init($asd);

echo $name; 
echo $code;
curl_init($command);
