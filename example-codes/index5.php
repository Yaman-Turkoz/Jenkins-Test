<?php

$name    = $_GET['name'];
$sorunlu = $_GET['cmd'];
$sorunlu2   = $_GET['code'];
$sorunsuz3 = 'a';

$sorunsuz = htmlspecialchars($name);
echo $sorunsuz;
echo $sorunlu;
echo $sorunlu2;
echo $sorunsuz3;

curl_init($sorunsuz);
curl_init($sorunlu);
curl_init($sorunlu2);
curl_init($sorunsuz3);

