<?php

$name    = $_GET['name'];
$command = $_GET['cmd'];
$code    = $_GET['code'];
$asd

$name = htmlspecialchars($name);
echo $name;

echo $code;

// Validate $name to prevent SSRF
$allowedHosts = array('http://example.com', 'https://example.com');
if (in_array($name, $allowedHosts)) {
    curl_init($name);
} else {
    echo "Invalid URL";
}

// $asd is not defined, this will cause an error
// curl_init($asd);

