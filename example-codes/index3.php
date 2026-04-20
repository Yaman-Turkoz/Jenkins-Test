<?php

$name    = $_GET['name'];
$command = $_GET['cmd'];
$code    = $_GET['code'];
$asd

$name = htmlspecialchars($name);
echo $name;
echo $command;

// Validate $name to prevent SSRF vulnerability
$allowedUrls = array('http://example.com', 'https://example.com');
if (in_array($name, $allowedUrls)) {
    curl_init($name);
} else {
    echo "Invalid URL";
}

// $asd is not defined, so we cannot use it here
// curl_init($asd);

