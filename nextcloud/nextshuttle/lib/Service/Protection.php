<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;
class Protection {
    public static function binding(array $row): string {
        $s=$row['secret'];
        return $row['kind']==='download'?'D2.'.$row['id'].'.'.$s['token'].'.'.$s['key'].'.'.$s['salt']:'U2.'.$row['id'].'.'.$s['public'].'.'.$s['salt'];
    }
    public static function root(string $binding,#[\SensitiveParameter] string $password): string {
        $parts=explode('.',$binding);$salt=sodium_base642bin(end($parts),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        if (strlen($salt)!==16||mb_strlen($password)<16||mb_strlen($password)>256) { throw new \UnexpectedValueException('Invalid encryption password or salt'); }
        return sodium_crypto_pwhash(32,$password,$salt,3,67108864,SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    }
    public static function key(string $binding,#[\SensitiveParameter] string $password,?string $seed=null): string {
        $root=self::root($binding,$password);
        try { return sodium_crypto_generichash('NextShuttle/v2/'.($seed===null?'file':'upload')."\0".$binding.($seed??''),$root,32); }
        finally { sodium_memzero($root); }
    }
    public static function authorization(string $binding,#[\SensitiveParameter] string $password): string {
        $root=self::root($binding,$password);
        try { return sodium_bin2base64(sodium_crypto_generichash("NextShuttle/v2/authorization\0".$binding,$root,32),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING); }
        finally { sodium_memzero($root); }
    }
}
