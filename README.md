<div align="center">
    <p><img src="https://jwt.io/img/logo-asset.svg" /></p>
    <p>A PHP extension for JSON Web Token (JWT)</p>
    <a target="_blank" href="https://travis-ci.org/cdoco/php-jwt" title="Build Status"><img src="https://travis-ci.org/cdoco/php-jwt.svg"></a>
    <img src="https://img.shields.io/badge/branch-master-brightgreen.svg?style=flat-square">
</div>

## Requirement

- PHP 7 +
- PHP json extension, need to json extension before loading JWT extension.
- OpenSSL (Version >= 1.0.1f) Might work with older version as well, but I did not check that.

## Install

```shell
$ git clone https://github.com/cdoco/php-jwt.git
$ cd php-jwt
$ phpize && ./configure --with-openssl=/path/to/openssl
$ make && make install
```

## Quick Example

```php
$key = "example-hmac-key";
$payload = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

// default HS256 algorithm
$token = jwt_encode($payload, $key);

//eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7Im5hbWUiOiJaaUhhbmcgR2FvIiwiYWRtaW4iOnRydWV9LCJpc3MiOiJodHRwOlwvXC9leGFtcGxlLm9yZyIsInN1YiI6IjEyMzQ1Njc4OTAifQ.UcrCt9o9rz38kKMTa-nCrm7JNQRNAId5Xg9C7EIl2Zc
echo $token;

$decoded_token = jwt_decode($token, $key);

// Array
// (
//    [data] => Array
//        (
//            [name] => ZiHang Gao
//            [admin] => 1
//        )
//
//    [iss] => http://example.org
//    [sub] => 1234567890
// )
print_r($decoded_token);
```

## Algorithms and Usage

### NONE

- none - unsigned token

```php
$payload = ['data' => 'test'];

// IMPORTANT: set null as key parameter
$token = jwt_encode($payload, null, 'none');

// eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJkYXRhIjoidGVzdCJ9.
echo $token;

// Set key to nil and options to false otherwise this won't work
$decoded_token = jwt_decode($token, null, false);

// Array
// (
//    [data] => test
// )
print_r($decoded_token);
```

#### HMAC (default: HS256)

- HS256 - HMAC using SHA-256 hash algorithm (default)
- HS384 - HMAC using SHA-384 hash algorithm
- HS512 - HMAC using SHA-512 hash algorithm

```php
$hmackey = "example-hmac-key";

$token = jwt_encode($payload, $hmackey, 'HS256');

// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.C8kzOqBbcaPRhRdLWdNVSvYkIPIBPu7f_8-avoG-JiU
echo $token;

$decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);

// Array
// (
//    [data] => test
// )
print_r($decoded_token);
```

### RSA

- RS256 - RSA using SHA-256 hash algorithm
- RS384 - RSA using SHA-384 hash algorithm
- RS512 - RSA using SHA-512 hash algorithm

```php
$privateKey = file_get_contents('key/rsa_private_key.pem');
$publicKey = file_get_contents('key/rsa_public_key.pem');

$token = jwt_encode($payload, $privateKey, 'RS256');

// eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.pkpKlkzQWSkme42WcOxwkLeUttiLeNORzthSJeIt140iNEtRK_f8IotoinfIKI7Y6x8pfQ4n1DHJ_5IUDe6elds8gnhLwfq5XRY48BGc8Dc_QowVQd75m5fXI6nFySW8z8CAsbwn2Efg-p7SLdfhWpNQ9AISfwa_1l-OB3BgKFw
echo $token;

$decoded_token = jwt_decode($token, $publicKey, ['algorithm' => 'RS256']);

// Array
// (
//    [data] => test
// )
print_r($decoded_token);
```

### ECDSA

- ES256 - ECDSA using P-256 and SHA-256
- ES384 - ECDSA using P-384 and SHA-384
- ES512 - ECDSA using P-521 and SHA-512

```php
$privateKey = file_get_contents('key/ec_private_key.pem');
$publicKey = file_get_contents('key/ec_public_key.pem');

$token = jwt_encode($payload, $privateKey, 'ES256');

// eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJkYXRhIjoidGVzdCJ9.etzxzSvJi1QS5nUtKDuLX2sScZ5W50CJL6PivKys45nc77QLxnLsF5QQApEAis8SI28rqwP9VITqPPlwJBNdH3N5n0I58z3jevGJYOfRtBnCa6omUNE03nxoEYMqRBuP
echo $token;

$decoded_token = jwt_decode($token, $publicKey, ['algorithm' => 'ES256']);

// Array
// (
//    [data] => test
// )
print_r($decoded_token);
```

## [Example](https://github.com/cdoco/php-jwt/tree/master/example)

## Benchmarks

![Benchmarks](https://cdoco.com/images/jwt-benchmarks.png "Benchmarks")

## Functions

```php
//encode
string jwt_encode(array $claims, string $key [, string $algorithm = 'HS256'])

//decode
array jwt_decode(string $token, string $key [, array $options = ['algorithm' => 'HS256']])
```

## The algorithm of support

algorithm|-|-|-
-|-|-|-
HMAC|HS256|HS384|HS512
RSA|RS256|RS384|RS512
ECDSA|ES256|ES384|ES512

## License

PHP License. See the [LICENSE](LICENSE) file.