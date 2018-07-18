--TEST--
Check for jwt aud claim name (string type)
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";
$payload = ['data' => 'data', 'aud' => 'Young'];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['aud' => 'Young', 'algorithm' => 'HS256']);
    echo "SUCCESS\n";
} catch (InvalidAudException $e) {
     // Handle invalid token
}

try {
    $decoded_token = jwt_decode($token, $hmackey, ['aud' => 'young', 'algorithm' => 'HS256']);
} catch (InvalidAudException $e) {
     // Handle invalid token
     echo "FAIL\n";
}
?>
--EXPECT--
SUCCESS
FAIL
