<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IUserManager;
use OCP\Share\IManager;
class Policy {
    public const DEFAULTS=['max_ttl'=>604800,'default_ttl'=>86400,'max_file'=>16777216,
        'max_active'=>100,'max_user_bytes'=>268435456,'max_downloads'=>10,
        'max_inbox_files'=>20,'max_inbox_bytes'=>134217728,'min_password'=>16,'require_download_password'=>false,'groups'=>[],
        'types'=>['txt','png','jpg','jpeg','pdf','docx','xlsx','pptx','zip']];
    public function __construct(private IConfig $config,private IGroupManager $groups,private IUserManager $users,private IManager $sharing) {}
    public function get(): array {
        $raw=$this->config->getAppValue('nextshuttle','policy','{}');
        $p=array_replace(self::DEFAULTS,json_decode($raw,true,16,JSON_THROW_ON_ERROR));
        $p['require_download_password']=$p['require_download_password']||$this->sharing->shareApiLinkEnforcePassword();return $p;
    }
    public function save(array $input): void {
        $p=array_replace($this->get(),array_intersect_key($input,self::DEFAULTS));
        foreach (['max_ttl'=>[60,604800],'default_ttl'=>[60,604800],'max_file'=>[1,33554432],
            'max_active'=>[1,1000],'max_user_bytes'=>[1,10737418240],'max_downloads'=>[1,1000],
            'max_inbox_files'=>[1,1000],'max_inbox_bytes'=>[1,1073741824],'min_password'=>[16,128]] as $key=>$range) {
            if (!is_int($p[$key])||$p[$key]<$range[0]||$p[$key]>$range[1]) { throw new \InvalidArgumentException('Invalid policy limit: '.$key); }
        }
        if ($p['default_ttl']>$p['max_ttl']) { throw new \InvalidArgumentException('Default lifetime exceeds maximum'); }
        if (!is_bool($p['require_download_password'])) { throw new \InvalidArgumentException('Invalid password policy'); }
        foreach (['groups','types'] as $key) {
            if (!is_array($p[$key])||count($p[$key])>100||array_filter($p[$key],static fn($v)=>!is_string($v))) { throw new \InvalidArgumentException('Invalid policy list'); }
            $p[$key]=array_values(array_unique($p[$key]));
        }
        if (!$p['types']||array_diff($p['types'],self::DEFAULTS['types'])) { throw new \InvalidArgumentException('Unsupported file type'); }
        foreach ($p['groups'] as $group) { if ($this->groups->get($group)===null) { throw new \InvalidArgumentException('Unknown eligible group'); } }
        $this->config->setAppValue('nextshuttle','policy',json_encode($p,JSON_THROW_ON_ERROR));
    }
    public function user(string $uid): void {
        $user=$this->users->get($uid); $p=$this->get();
        if ($user===null||!$user->isEnabled()||!$this->sharing->shareApiEnabled()
            ||!$this->sharing->shareApiAllowLinks($user)||$this->sharing->sharingDisabledForUser($uid)
            ||($p['groups']&&!array_intersect($p['groups'],$this->groups->getUserGroupIds($user)))) {
            throw new \OCP\Files\NotPermittedException('NextShuttle sharing is not allowed for this account');
        }
    }
    public function options(string $uid,string $kind,array $data): array {
        $this->user($uid); $p=$this->get(); $ttl=$data['ttl']??$p['default_ttl'];
        if ($this->sharing->shareApiLinkDefaultExpireDateEnforced()) { $p['max_ttl']=min($p['max_ttl'],$this->sharing->shareApiLinkDefaultExpireDays()*86400); }
        if (!is_int($ttl)||$ttl<60||$ttl>$p['max_ttl']) { throw new \InvalidArgumentException('Invalid transfer lifetime'); }
        $out=['ttl'=>$ttl,'policy'=>$p];
        if ($kind==='download') {
            $n=$data['max_uses']??1; if (!is_int($n)||$n<1||$n>$p['max_downloads']) { throw new \InvalidArgumentException('Invalid download limit'); } $out['max_uses']=$n;
        } else {
            if (!$this->sharing->shareApiLinkAllowPublicUpload()) { throw new \OCP\Files\NotPermittedException('Public uploads are disabled in Nextcloud'); }
            $n=$data['max_files']??$p['max_inbox_files']; $b=$data['max_bytes']??$p['max_inbox_bytes'];
            if (!is_int($n)||$n<1||$n>$p['max_inbox_files']||!is_int($b)||$b<1||$b>$p['max_inbox_bytes']) { throw new \InvalidArgumentException('Invalid inbox limits'); }
            $out+=['max_files'=>$n,'max_bytes'=>$b];
        }
        return $out;
    }
    public function file(string $name,int $size): void {
        $p=$this->get(); FileCrypto::safeName($name);
        if ($size<1||$size>$p['max_file']||!in_array(strtolower(pathinfo($name,PATHINFO_EXTENSION)),$p['types'],true)) { throw new ScanRejected('content_rejected'); }
    }
}
