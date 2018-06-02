--TEST--
Check for jwt claim name
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";
$payload = ['data' => 'data', 'sub' => '1234567890'];

$token = jwt_encode($payload, $hmackey);

try {
    $decoded_token = jwt_decode($token, $hmackey, ['iss' => 'http://example.org']);
    echo "SUCCESS\n";
} catch (Exception $e) {
    // Expired token
}
?>
--EXPECT--
SUCCESS
