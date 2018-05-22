<?php

$key = "example_key";
$claims = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

// default HS256 algorithm
$token = jwt_encode($claims, $key);

echo $token . PHP_EOL;
print_r(jwt_decode($token, $key));