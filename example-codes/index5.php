<?php

$name    = $_GET['name'];
$command = $_GET['cmd'];
$code    = $_GET['code'];
$asd

$name = htmlspecialchars($name);
$command = htmlspecialchars($command);
$code = htmlspecialchars($code);

echo $name;
echo $command;
echo $code;

curl_init($name);
curl_init($code);
curl_init($asd);

