--TEST--
Check for jwt HMAC algorithm (HS256)
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php 
$key = "example_key";
$claims = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

$token = jwt_encode($claims, $key);

echo $token . PHP_EOL;
print_r(jwt_decode($token, $key));
?>
--EXPECT--
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7Im5hbWUiOiJaaUhhbmcgR2FvIiwiYWRtaW4iOnRydWV9LCJpc3MiOiJodHRwOlwvXC9leGFtcGxlLm9yZyIsInN1YiI6IjEyMzQ1Njc4OTAifQ.6BafFmznKQOPVO9q5f5GgTVadITh2KmdUlJBF8UHOxo
Array
(
    [data] => Array
        (
            [name] => ZiHang Gao
            [admin] => 1
        )

    [iss] => http://example.org
    [sub] => 1234567890
)
