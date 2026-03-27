<?php
// Kullanıcıdan gelen ham girdi — doğrulama yok
$name    = $_GET['name'];
$command = $_GET['cmd'];
$code    = $_GET['code'];

// XSS: kullanıcı girdisi doğrudan çıktılanıyor
echo $name;

// Debug: hassas veri sızdırabilir
var_dump($name);

// RCE: kullanıcı girdisi doğrudan eval'e gönderiliyor
eval($code);

// Command Injection: kullanıcı girdisi shell'e gönderiliyor
$output = shell_exec($command);
echo $output;

echo $output;

echo $name;
