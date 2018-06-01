<?php

$privateKey = <<<EOD
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBeLCgapjZmvTatMHaYX3A02+0Ys3Tr8kda+E9DFnmCSiCOEig519fT
13edeU8YdDugBwYFK4EEACKhZANiAASibEL3JxzwCRdLBZCm7WQ3kWaDL+wP8omo
3e2VJmZQRnfDdzopgl8r3s8w5JlBpR17J0Gir8g6CVBA6PzMuq5urkilppSINDnR
4mDv0+9e4uJVQf3xwEv+jywNUH+wbPM=
-----END EC PRIVATE KEY-----
EOD;

$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEomxC9ycc8AkXSwWQpu1kN5Fmgy/sD/KJ
qN3tlSZmUEZ3w3c6KYJfK97PMOSZQaUdeydBoq/IOglQQOj8zLqubq5IpaaUiDQ5
0eJg79PvXuLiVUH98cBL/o8sDVB/sGzz
-----END PUBLIC KEY-----
EOD;

$payload = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

$token = jwt_encode($payload, $privateKey, 'ES256');

echo $token . PHP_EOL;
print_r(jwt_decode($token, $publicKey, ['algorithm' => 'ES256']));