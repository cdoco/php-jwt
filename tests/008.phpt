--TEST--
Check for jwt iat claim name
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";
$payload = ['data' => 'data', 'iat' => time()];
$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);
    echo "SUCCESS\n";
} catch (InvalidIatException $e) {
     // Handle invalid token
}
?>
--EXPECT--
SUCCESS

