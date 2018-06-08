--TEST--
Check for jwt iss claim name
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";
$payload = ['data' => 'data', 'iss' => 'http://example.org'];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['iss' => 'http://example.org', 'algorithm' => 'HS256']);
    echo "SUCCESS\n";
} catch (InvalidIssuerException $e) {
     // Handle invalid token
}

try {
    $decoded_token = jwt_decode($token, $hmackey, ['iss' => 'test', 'algorithm' => 'HS256']);
} catch (InvalidIssuerException $e) {
     // Handle invalid token
     echo "FAIL\n";
}
?>
--EXPECT--
SUCCESS
FAIL
