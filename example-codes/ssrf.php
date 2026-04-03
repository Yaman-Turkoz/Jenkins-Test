<?php

$allowed_domains = array(
    "example.com",
    "example.org"
);


$url = $_GET['url'];


$domain = parse_url($url, PHP_URL_HOST);
if (!in_array($domain, $allowed_domains)) {
    echo "Access to the specified URL is not allowed.";
    exit;
}


$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, $url);
curl_setopt($curl, CURLOPT_RETURNTRANSFER,1);
curl_setopt($curl, CURLOPT_TIMEOUT, 5);
curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
$data = curl_exec ($curl);
if(curl_error($curl)){
    echo curl_error($curl);
}else{
    echo "<pre>" . $data . "</pre>";
}
curl_close ($curl);
?>
