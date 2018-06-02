--TEST--
Check for jwt NONE algorithm
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php 

$payload = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

// none algorithm
$token = jwt_encode($payload, null, 'none');

echo $token . PHP_EOL;
print_r(jwt_decode($token, null, false));
?>
--EXPECT--
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJkYXRhIjp7Im5hbWUiOiJaaUhhbmcgR2FvIiwiYWRtaW4iOnRydWV9LCJpc3MiOiJodHRwOlwvXC9leGFtcGxlLm9yZyIsInN1YiI6IjEyMzQ1Njc4OTAifQ.
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
