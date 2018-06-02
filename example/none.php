<?php

$payload = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

// none algorithm
$token = jwt_encode($payload, null, 'none');

echo $token . PHP_EOL;
print_r(jwt_decode($token, null, false));