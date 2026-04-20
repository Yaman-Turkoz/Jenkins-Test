<?php

$name    = $_GET['name'];
$command = $_GET['cmd'];
$code    = $_GET['code'];
$asd

$name = htmlspecialchars($name);
echo $name;
echo $command;

// Validate $name to prevent SSRF
$allowedUrls = array('http://example.com', 'https://example.com');
if (in_array($name, $allowedUrls)) {
    curl_init($name);
} else {
    echo "Invalid URL";
}

// $asd is not defined, so this will cause an error
// curl_init($asd);

