<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;

/** Versioned framing around libsodium secretstream, interoperable with web/crypto.mjs. */
class FileCrypto {
    public const MAX_PLAIN = 33554432;
    public const MAX_CIPHER = 35651584;
    public const CHUNK = 65536;
    public static function safeName(string $name): string {
        if ($name === '' || strlen($name) > 240 || !preg_match('//u', $name)
            || preg_match('/[\x00-\x1f\x7f\/\\\\:]/u', $name) || $name[0] === '.'
            || preg_match('/[. ]$/D', $name) || preg_match('/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i', $name)) {
            throw new \UnexpectedValueException('Unsafe filename');
        }
        return $name;
    }
    private static function exact($stream, int $length): string {
        $value = '';
        while (strlen($value) < $length) {
            $chunk = fread($stream, $length - strlen($value));
            if ($chunk === false || $chunk === '') { throw new \UnexpectedValueException('Truncated encrypted file'); }
            $value .= $chunk;
        }
        return $value;
    }
    private static function frame($out, string &$state, string $data, string $prefix, int $tag): void {
        $cipher = sodium_crypto_secretstream_xchacha20poly1305_push($state, $data, $prefix, $tag);
        $raw = pack('N', strlen($cipher)) . $cipher;
        if (fwrite($out, $raw) !== strlen($raw)) { throw new \RuntimeException('Staging disk write failed'); }
    }
    public static function encrypt($in, $out, string $name, int $size, ?string $boxPublic = null): string {
        self::safeName($name);
        if ($size < 1 || $size > self::MAX_PLAIN) { throw new \UnexpectedValueException('Invalid file size'); }
        $key = sodium_crypto_secretstream_xchacha20poly1305_keygen();
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $prefix = $boxPublic === null ? 'NSH1D' : 'NSH1U';
        fwrite($out, $prefix . ($boxPublic === null ? '' : sodium_crypto_box_seal($key, $boxPublic)) . $header);
        $meta = json_encode(['name' => $name, 'size' => $size], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        self::frame($out, $state, $meta, $prefix, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
        $read = 0;
        while (!feof($in)) {
            $chunk = fread($in, self::CHUNK);
            if ($chunk === false) { throw new \RuntimeException('Staging read failed'); }
            if ($chunk === '') { break; }
            $read += strlen($chunk);
            if ($read > $size) { throw new \UnexpectedValueException('File size changed'); }
            self::frame($out, $state, $chunk, $prefix, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE);
        }
        if ($read !== $size) { throw new \UnexpectedValueException('File size changed'); }
        self::frame($out, $state, '', $prefix, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
        return $key;
    }
    public static function decrypt($in, $out, ?string $key = null, ?string $boxKeypair = null): array {
        $prefix = self::exact($in, 5);
        if (!in_array($prefix, ['NSH1D', 'NSH1U'], true)) { throw new \UnexpectedValueException('Unsupported encrypted format'); }
        if ($prefix === 'NSH1U') {
            if ($boxKeypair === null) { throw new \UnexpectedValueException('Inbox key required'); }
            $key = sodium_crypto_box_seal_open(self::exact($in, 80), $boxKeypair);
        }
        if (!is_string($key) || strlen($key) !== 32) { throw new \UnexpectedValueException('Invalid file key'); }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull(self::exact($in, 24), $key);
        $pull = static function () use ($in, &$state, $prefix): array {
            $size = unpack('Nsize', self::exact($in, 4))['size'];
            if ($size < 17 || $size > self::CHUNK + 17) { throw new \UnexpectedValueException('Invalid chunk size'); }
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, self::exact($in, $size), $prefix);
            if ($result === false) { throw new \UnexpectedValueException('Authentication failed'); }
            return $result;
        };
        [$manifest, $tag] = $pull();
        if ($tag !== 0 || strlen($manifest) > 4096) { throw new \UnexpectedValueException('Invalid encrypted manifest'); }
        $meta = json_decode($manifest, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($meta) || !is_string($meta['name'] ?? null) || !is_int($meta['size'] ?? null)
            || $meta['size'] < 1 || $meta['size'] > self::MAX_PLAIN) { throw new \UnexpectedValueException('Invalid file metadata'); }
        self::safeName($meta['name']); $total = 0;
        while (true) {
            [$data, $tag] = $pull();
            if ($tag === 3) {
                if ($data !== '' || fread($in, 1) !== '') { throw new \UnexpectedValueException('Appended stream data'); }
                break;
            }
            if ($tag !== 0 || $data === '') { throw new \UnexpectedValueException('Invalid data frame'); }
            $total += strlen($data);
            if ($total > $meta['size'] || fwrite($out, $data) !== strlen($data)) { throw new \UnexpectedValueException('Plaintext limit or disk failure'); }
        }
        if ($total !== $meta['size']) { throw new \UnexpectedValueException('Incomplete encrypted file'); }
        return $meta;
    }
}
