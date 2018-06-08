--TEST--
Check for jwt exp claim name (Expired token)
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php 
$hmackey = "example-hmac-key";
$payload = ['data' => 'data', 'exp' => time() - 10];
$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);
} catch (ExpiredSignatureException $e) {
    // Expired token
    echo $e->getMessage() . "\n";
}

try {
    $decoded_token = jwt_decode($token, $hmackey, ['leeway' => 30, 'algorithm' => 'HS256']);
    echo "Success\n";
} catch (ExpiredSignatureException $e) {
    // Expired token
}
?>
--EXPECT--
Expired token
Success
