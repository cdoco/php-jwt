# php-jwt

[![Build Status][travis-image]][travis-url]
![Branch master](https://img.shields.io/badge/branch-master-brightgreen.svg?style=flat-square)

> A PHP extension for JSON Web Token

## Requirement

- PHP 7 +

## Install

```shell
$ git clone https://github.com/cdoco/php-jwt.git
$ cd php-jwt
$ phpize && ./configure --with-openssl=/path/to/openssl
$ make && make install
```

## Quick Example

```php
$key = "example_key";
$claims = array(
    "data" => [
        "name" => "ZiHang Gao",
        "admin" => true
    ],
    "iss" => "http://example.org",
    "sub" => "1234567890",
);

// default HS256 algorithm
$token = jwt_encode($claims, $key);

echo $token . PHP_EOL;
//eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
//eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLm9yZyIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiWmlIYW5nIEdhbyIsImFkbWluIjp0cnVlfQ.
//2lFeBTsRegsjXiBCZNkW41KFlsZPSFu7KTsyAM9lUiQ

print_r(jwt_decode($token, $key));
/**
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
*/
```

## [Example](https://github.com/cdoco/php-jwt/tree/master/example)

## Benchmarks

![Benchmarks](https://cdoco.com/images/jwt-benchmarks.png "Benchmarks")

## Methods

```php
//encode
string jwt_encode(array $claims, string $key [, string $alg = 'HS256'])

//decode
array jwt_decode(string $token, string $key [, string $alg = 'HS256'])
```

## The algorithm of support

algorithm|-|-|-
-|-|-|-
HMAC|HS256|HS384|HS512
RSA|RS256|RS384|RS512
ECDSA|ES256|ES384|ES512

## License

PHP License. See the [LICENSE](LICENSE) file.

[travis-url]: https://travis-ci.org/cdoco/php-jwt
[travis-image]: https://travis-ci.org/cdoco/php-jwt.svg