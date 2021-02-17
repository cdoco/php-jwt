[![Build Status][travis-image]][travis-url]
![PHP](https://img.shields.io/badge/PHP-%3E%3D7.0.0-orange.svg)
![OpenSSL](https://img.shields.io/badge/OpenSSL-%3E%3D1.0.1f-orange.svg)
![branch](https://img.shields.io/badge/branch-master-brightgreen.svg)
![license](https://img.shields.io/badge/License-PHP/3.01-blue.svg)

> A PHP extension for [RFC 7519 OAuth JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

## Requirement

- PHP 7 +
- PHP json extension, need to json extension before loading JWT extension.
- OpenSSL (Version >= 1.1.0j) Might work with older version as well, but I did not check that.

## Install

```shell
$ git clone https://github.com/cdoco/php-jwt.git
$ cd php-jwt
$ phpize && ./configure --with-openssl=/path/to/openssl
$ make && make install
```

## Quick [Example](https://github.com/cdoco/php-jwt/tree/master/example)

```php
$key = "example-hmac-key";
$payload = [
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
];

// default HS256 algorithm
$token = jwt_encode($payload, $key);

// eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7Im5hbWUiOiJaaUhhbmcgR2FvIiwiYWRtaW4iOnRydWV9LCJpc3MiOiJodHRwOlwvXC9leGFtcGxlLm9yZyIsInN1YiI6IjEyMzQ1Njc4OTAifQ.UcrCt9o9rz38kKMTa-nCrm7JNQRNAId5Xg9C7EIl2Zc
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

// or would you prefer to use a static method call
$token = \Cdoco\JWT::encode($payload, $key);
$decoded_token = \Cdoco\JWT::decode($token, $key);
```

## Algorithms and Usage

The JWT supports NONE, HMAC, RSASSA and ECDSA algorithms for cryptographic signing.

#### NONE

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

#### RSA

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

#### ECDSA

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

## Support for reserved claim names

JSON Web Token defines some reserved claim names and defines how they should be used. JWT supports these reserved claim names:

- 'exp' (Expiration Time) Claim
- 'nbf' (Not Before Time) Claim
- 'iss' (Issuer) Claim
- 'aud' (Audience) Claim
- 'jti' (JWT ID) Claim
- 'iat' (Issued At) Claim
- 'sub' (Subject) Claim

### Expiration Time Claim

> The `exp` (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for processing. The processing of the `exp` claim requires that the current date/time MUST be before the expiration date/time listed in the `exp` claim. Implementers MAY provide for some small `leeway`, usually no more than a few minutes, to account for clock skew. Its value MUST be a number containing a **NumericDate** value. Use of this claim is OPTIONAL.

#### Handle Expiration Claim

```php
$payload = ['data' => 'data', 'exp' => time() + 4 * 3600];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);
} catch (ExpiredSignatureException $e) {
    // Expired token
}
```

#### Adding Leeway

```php
$payload = ['data' => 'data', 'exp' => time() - 10];

// build expired token
$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['leeway' => 30, 'algorithm' => 'HS256']);
} catch (ExpiredSignatureException $e) {
    // Expired token
}
```

### Not Before Time Claim

> The `nbf` (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing. The processing of the `nbf` claim requires that the current date/time MUST be after or equal to the not-before date/time listed in the `nbf` claim. Implementers MAY provide for some small `leeway`, usually no more than a few minutes, to account for clock skew. Its value MUST be a number containing a **NumericDate** value. Use of this claim is OPTIONAL.

#### Handle Not Before Claim

```php
$payload = ['data' => 'data', 'nbf' => time() - 3600];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);
} catch (BeforeValidException $e) {
    // Handle invalid token
}
```

#### Adding Leeway

```php
$payload = ['data' => 'data', 'nbf' => time() + 10];

// build expired token
$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['leeway' => 30, 'algorithm' => 'HS256']);
} catch (BeforeValidException $e) {
    // Handle invalid token
}
```

### Issuer Claim

> The `iss` (issuer) claim identifies the principal that issued the JWT. The processing of this claim is generally application specific. The `iss` value is a case-sensitive string containing a **StringOrURI** value. Use of this claim is OPTIONAL.

```php
$payload = ['data' => 'data', 'iss' => 'http://example.org'];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['iss' => 'http://example.org', 'algorithm' => 'HS256']);
} catch (InvalidIssuerException $e) {
     // Handle invalid token
}
```

### Audience Claim

> The `aud` (audience) claim identifies the recipients that the JWT is intended for. Each principal intended to process the JWT MUST identify itself with a value in the audience claim. If the principal processing the claim does not identify itself with a value in the `aud` claim when this claim is present, then the JWT MUST be rejected. In the general case, the `aud` value is an array of case-sensitive strings, each containing a **StringOrURI** value. In the special case when the JWT has one audience, the `aud` value MAY be a single case-sensitive string containing a **StringOrURI** value. The interpretation of audience values is generally application specific. Use of this claim is OPTIONAL.

```php
$payload = ['data' => 'data', 'aud' => ['Young', 'Old']];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['aud' => ['Young', 'Old'], 'algorithm' => 'HS256']);
} catch (InvalidAudException $e) {
     // Handle invalid token
}
```

### JWT ID Claim

> The `jti` (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST be assigned in a manner that ensures that there is a negligible probability that the same value will be accidentally assigned to a different data object; if the application uses multiple issuers, collisions MUST be prevented among values produced by different issuers as well. The `jti` claim can be used to prevent the JWT from being replayed. The `jti` value is a **case-sensitive string**. Use of this claim is OPTIONAL.

```php
$payload = ['data' => 'data', 'jti' => md5('id')];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['jti' => md5('id'), 'algorithm' => 'HS256']);
} catch (InvalidJtiException $e) {
     // Handle invalid token
}
```

### Issued At Claim

> The `iat` (issued at) claim identifies the time at which the JWT was issued. This claim can be used to determine the age of the JWT. Its value MUST be a number containing a **NumericDate** value. Use of this claim is OPTIONAL.

```php
$payload = ['data' => 'data', 'iat' => time()];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['algorithm' => 'HS256']);
} catch (InvalidIatException $e) {
     // Handle invalid token
}
```

### Subject Claim

> The `sub` (subject) claim identifies the principal that is the subject of the JWT. The Claims in a JWT are normally statements about the subject. The subject value MUST either be scoped to be locally unique in the context of the issuer or be globally unique. The processing of this claim is generally application specific. The sub value is a case-sensitive string containing a **StringOrURI** value. Use of this claim is OPTIONAL.

```php
$payload = ['data' => 'data', 'sub' => 'Subject'];

$token = jwt_encode($payload, $hmackey, 'HS256');

try {
    $decoded_token = jwt_decode($token, $hmackey, ['sub' => 'Subject', 'algorithm' => 'HS256']);
} catch (InvalidSubException $e) {
     // Handle invalid token
}
```

## Benchmarks

![Benchmarks](https://cdoco.com/images/jwt-benchmarks.png "Benchmarks")

## Functions

```php
// encode
string jwt_encode(array $payload, string $key [, string $algorithm = 'HS256'])

// decode
array jwt_decode(string $token, string $key [, array $options = ['algorithm' => 'HS256']])
```

## IDE Helper

```php
<?php
/**
 * Put this file into root of your project for IDE helper
 * Note: This file don't need to be require/include
 */
namespace {
    function jwt_encode(array $payload, string $key, string $algorithm = 'HS256'): string
    {
        return '';
    }

    function jwt_decode(string $token, string $key, string $algorithm = 'HS256'): array
    {
        return [];
    }
}

namespace Cdoco {
    // @codingStandardsIgnoreStart
    abstract class JWT
    // @codingStandardsIgnoreEnd
    {
        abstract public static function encode(array $payload, string $key, string $algorithm = 'HS256'): string;

        abstract public static function decode(string $token, string $key, string $algorithm = 'HS256'): array;
    }
}
```

## The algorithm of support

algorithm|-|-|-
-|-|-|-
HMAC|HS256|HS384|HS512
RSA|RS256|RS384|RS512
ECDSA|ES256|ES384|ES512

## Inspired By

- <https://github.com/benmcollins/libjwt>
- <https://github.com/firebase/php-jwt>
- <https://github.com/kohkimakimoto/php-jwt>
- <https://github.com/jwt/ruby-jwt>

## License

PHP License 3.01. See the [LICENSE](LICENSE) file.

[travis-url]: https://travis-ci.org/cdoco/php-jwt
[travis-image]: https://travis-ci.org/cdoco/php-jwt.svg
