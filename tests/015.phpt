--TEST--
ISSUE #21 Segmentation fault of php-fpm instance on jwt_decode
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
$hmackey = "example-hmac-key";

try {
    $decoded_token = jwt_decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7Im5hbWUiOiJaaUhhbmcgR2FvIiwiYWRtaW4iOnRydWV9LCJzdWIiOiIxMjM0NTY3ODkwIiwibmJmIjoxNTQ2ODQ4CJhdWQiOiJ5eSJ9.fDqiF-cCIvlcscIdz7dcFJoYGBcvHtI6MWB5IWG0VHA', $hmackey, ['algorithm' => 'HS256']);
} catch (SignatureInvalidException $e) {
     // Handle expired token
     echo "FAIL\n";
}
?>
--EXPECT--
FAIL
