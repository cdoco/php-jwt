# php-jwt

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
    "iss" => "http://example.org",
    "sub" => "1234567890",
    "name" => "ZiHang Gao",
    "admin" => true
);

jwt_encode($claims, $key);
//eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.
//eyJpc3MiOiJodHRwOlwvXC9leGFtcGxlLm9yZyIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiWmlIYW5nIEdhbyIsImFkbWluIjp0cnVlfQ.
//2lFeBTsRegsjXiBCZNkW41KFlsZPSFu7KTsyAM9lUiQ

jwt_decode($jwt, $key);
//array(4) {
//  'iss' =>
//  string(18) "http://example.org"
//  'sub' =>
//  string(10) "1234567890"
//  'name' =>
//  string(10) "ZiHang Gao"
//  'admin' =>
//  bool(true)
//}
```

## RSA

```php
$privateKey = <<<EOD
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAK4DlHRtn1sLFBlD
WvDd87Z6vA9AKnXHslxhQHJtUigfd2BmuFSwBR8BfNrLbvhKTiZiGyLn9di6c7I2
4awHALyPcqkrayNva74GUKacwL6E2OCjmW1qW9EYwQfFrS6k4CkkjHN7sGC3vV6x
YJ07F8yKL1tSdHy1J3BSojfXX3MBAgMBAAECgYEAkPVGe969+xe1fH4Rick7Nm3z
rziipk7ek/ont6q939KmnVW0hEfFXFje61zAanFrvKnJNUDKGeroajMxtx52SzyS
BiNWGfZAKMsQ1fQA7f99UkJcRD/KjpjeGTTgMVJLXrYj3P7iCVUmDdZ183YYjfzd
eYtFsh5GJvZugL4NAYkCQQDnJ+ox4uG1Scchz2R7JZvM621eQUoAtnQjDQJZrsD5
mujsAHeaVzMPntzPf6+waCFCU+SKDkUAVqAlZ2RGt+iXAkEAwLdyYCh4SdrX/qJ4
t/IZzDdOQ/j7qF+uLcEQ6kQxWtHuKbK/oWSLOmB/eqSgK548ABGaZe40wvwsON7s
OjmcJwJAbKKFngxSpzCVNX6Sao2yOwwpyjJE5TDaQ97JS/ylFKmI7eEKVK7GgIDY
pWwM1YsalmF29qreItqTSQDeT53+4QJAYp49oGl1TM35lCuOPQteGjv/CBekqH/2
ASH4RvmIjCI7jwkSuUNbYA87jQYrlMaPi7V2XkzsoQ8sjhm9pvoOJwJBAL8g8gsS
2KvzMb6XeAn6PIsbn1JDP7bwyV+YZeO2yxAU8Fi1GjgVsE7B2eAZnLFyVO+6mrTB
lnPABViHef6hEJE=
-----END PRIVATE KEY-----
EOD;

$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuA5R0bZ9bCxQZQ1rw3fO2erwP
QCp1x7JcYUBybVIoH3dgZrhUsAUfAXzay274Sk4mYhsi5/XYunOyNuGsBwC8j3Kp
K2sjb2u+BlCmnMC+hNjgo5ltalvRGMEHxa0upOApJIxze7Bgt71esWCdOxfMii9b
UnR8tSdwUqI3119zAQIDAQAB
-----END PUBLIC KEY-----
EOD;

$jwt = jwt_encode([
    "iss" => "http://example.org",
    "sub" => "1234567890",
    "name" => "ZiHang Gao",
    "admin" => true
], $privateKey, 'RS512');

jwt_decode($jwt, $publicKey, 'RS512');
```
