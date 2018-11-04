--TEST--
ISSUE #18 expiration time bug
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";

try {
    $decoded_token = jwt_decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiZGF0YSIsImV4cCI6MTU0MTMzNTUxNH0.CsQXJI3d2b9LOZSO3rD2xrr9ar7bWBcbrrm-mXJto3g', $hmackey, ['algorithm' => 'HS256']);
} catch (ExpiredSignatureException $e) {
     // Handle expired token
     echo "FAIL\n";
}
?>
--EXPECT--
FAIL
