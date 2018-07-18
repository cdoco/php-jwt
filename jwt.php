<?php
$br = (php_sapi_name() == "cli")? "":"<br>";

if(!extension_loaded('jwt')) {
	dl('jwt.' . PHP_SHLIB_SUFFIX);
}

use Cdoco\JWT;

$key = "example_key";
$claims = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "sub" => "1234567890",
    "nbf" => time() + 1,
    "aud" => 'yy',
);

// default HS256 algorithm
$token = JWT::encode($claims, $key);

echo $token . PHP_EOL;
print_r(JWT::decode($token, $key, ["audx" => 'yy', 'leeway' => 2, "iss" => "http://example.org"]));
