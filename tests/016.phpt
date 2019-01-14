--TEST--
ISSUE #23 Segfault with multiple jwt_decode using RSA
--SKIPIF--
<?php if (!extension_loaded("jwt")) print "skip"; ?>
--FILE--
<?php
function generateKeyPair()
{
  $key = openssl_pkey_new([
    'digest_alg' => 'sha512',
    'private_key_bits' => 1024,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
  ]);
  openssl_pkey_export($key, $private);
  $public = openssl_pkey_get_details($key)['key'];
  openssl_pkey_free($key);
  return [$public, $private];
}

list($apub, $apriv) = generateKeyPair();
list($bpub, $bpriv) = generateKeyPair();

$payload = ['message' => 'hello world'];
$token = jwt_encode($payload, $apriv, 'RS512');
$decoded = jwt_decode($token, $apub, ['algorithm' => 'RS512']);
print_r($decoded);

$payload = ['message' => 'hello world 2'];
$token = jwt_encode($payload, $bpriv, 'RS512');
$decoded = jwt_decode($token, $bpub, ['algorithm' => 'RS512']);
print_r($decoded);
?>
--EXPECT--
Array
(
    [message] => hello world
)
Array
(
    [message] => hello world 2
)
