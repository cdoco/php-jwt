<?php
$br = (php_sapi_name() == "cli")? "":"<br>";

if(!extension_loaded('jwt')) {
	dl('jwt.' . PHP_SHLIB_SUFFIX);
}

$key = "example_key";
$claims = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "sub" => "1234567890",
    "nbf" => time() + 100
);

// default HS256 algorithm
$token = jwt_encode($claims, $key);

echo $token . PHP_EOL;
print_r(jwt_decode($token, $key, ['leeway' => 2, "iss" => "http://example.org"]));
