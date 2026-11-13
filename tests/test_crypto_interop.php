<?php
declare(strict_types=1);
require __DIR__ . '/../nextcloud/nextshuttle/lib/Service/FileCrypto.php';
use OCA\NextShuttle\Service\FileCrypto;
$path = $argv[1];
$decode = static fn(string $v): string => sodium_base642bin($v, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
$encode = static fn(string $v): string => sodium_bin2base64($v, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
$meta = json_decode(file_get_contents($path . '/js-meta.json'), true, 8, JSON_THROW_ON_ERROR);
$pair = sodium_crypto_box_keypair_from_secretkey_and_publickey($decode($meta['private']), $decode($meta['public']));
foreach (['download','upload'] as $kind) {
    $in = fopen($path . '/js-' . $kind . '.bin', 'rb'); $out = tmpfile();
    $info = FileCrypto::decrypt($in, $out, $kind === 'download' ? $decode($meta['key']) : null, $pair);
    rewind($out);
    if ($info['name'] !== 'interop ü.txt' || stream_get_contents($out) !== str_repeat('A', 70001)) { throw new RuntimeException('JS interoperability failed'); }
    fclose($in); fclose($out);
}
$raw = file_get_contents($path . '/js-download.bin');
foreach ([substr($raw, 0, -1), $raw . 'x', substr_replace($raw, chr(ord($raw[40]) ^ 1), 40, 1)] as $bad) {
    $in = tmpfile(); fwrite($in, $bad); rewind($in); $out = tmpfile();
    try { FileCrypto::decrypt($in, $out, $decode($meta['key'])); throw new RuntimeException('Corruption accepted'); }
    catch (UnexpectedValueException $expected) {}
    finally { fclose($in); fclose($out); }
}
$box = sodium_crypto_box_keypair();
foreach (['download','upload'] as $kind) {
    $in = tmpfile(); fwrite($in, str_repeat('A', 70001)); rewind($in);
    $out = fopen($path . '/php-' . $kind . '.bin', 'wb');
    $key = FileCrypto::encrypt($in, $out, 'interop ü.txt', 70001, $kind === 'upload' ? sodium_crypto_box_publickey($box) : null);
    if ($kind === 'download') { $downloadKey = $key; }
    fclose($in); fclose($out);
}
file_put_contents($path . '/php-meta.json', json_encode(['key' => $encode($downloadKey),
    'public' => $encode(sodium_crypto_box_publickey($box)), 'private' => $encode(sodium_crypto_box_secretkey($box))], JSON_THROW_ON_ERROR));
echo "JavaScript ↔ PHP decryption and corruption checks passed.\n";
