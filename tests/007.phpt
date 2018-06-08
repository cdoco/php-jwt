--TEST--
Check for jwt nbf claim name
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";
$payload = ['data' => 'data', 'nbf' => time() + 10];
$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);
} catch (BeforeValidException $e) {
    // Expired token
    echo "FAIL\n";
}

try {
    $decoded_token = jwt_decode($token, $hmackey, ['leeway' => 30, 'algorithm' => 'HS256']);
    echo "SUCCESS\n";
} catch (BeforeValidException $e) {
    // Expired token
}
?>
--EXPECT--
FAIL
SUCCESS
