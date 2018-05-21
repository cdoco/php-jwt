<?php
$br = (php_sapi_name() == "cli")? "":"<br>";

if(!extension_loaded('jwt')) {
	dl('jwt.' . PHP_SHLIB_SUFFIX);
}

$jwt = jwt_encode([
	"iss" => "http://example.org",
], 'example_key', 'HS512');

var_dump(jwt_decode($jwt, 'example_key', 'HS512'));
