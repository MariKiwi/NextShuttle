<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IRootFolder;
use OCP\IConfig;
use OCP\ITempManager;
use OCP\Lock\ILockingProvider;
class Shuttle {
    public function __construct(private Transfers $transfers,private Policy $policy,private Relay $relay,
        private Events $events,private IRootFolder $root,private ITempManager $temp,
        private ILockingProvider $locks,private IConfig $config) {}
    private function locked(string $id,callable $work): mixed {
        if (!$this->config->getSystemValueBool('filelocking.enabled',true)) { throw new \RuntimeException('File locking must be enabled'); }
        $key='nextshuttle/'.hash('sha256',$id); $this->locks->acquireLock($key,ILockingProvider::LOCK_EXCLUSIVE);
        try { return $work(); } finally { $this->locks->releaseLock($key,ILockingProvider::LOCK_EXCLUSIVE); }
    }
    public function node(string $uid,int $id,string $kind): File|Folder {
        $this->policy->user($uid); $nodes=$this->root->getUserFolder($uid)->getById($id);
        foreach ($nodes as $node) {
            if (!$node->isShareable()||!$node->isReadable()) { continue; }
            $owner=$node->getOwner();
            if (($owner===null||$owner->getUID()!==$uid)&&$this->config->getAppValue('core','shareapi_allow_resharing','yes')!=='yes') { continue; }
            if ($kind==='download'&&$node instanceof File) { return $node; }
            if ($kind==='inbox'&&$node instanceof Folder&&$node->isCreatable()) { return $node; }
        }
        throw new \OCP\Files\NotPermittedException('File or folder is not accessible for this transfer');
    }
    public function create(string $uid,string $kind,int $nodeId,#[\SensitiveParameter] array $data): array {
        if (!in_array($kind,['download','inbox'],true)) { throw new \InvalidArgumentException('Unsupported transfer'); }
        return $this->locked('quota/'.$uid,function() use ($uid,$kind,$nodeId,$data): array {
            $options=$this->policy->options($uid,$kind,$data); $node=$this->node($uid,$nodeId,$kind); $p=$this->policy->get();
            $active=array_filter($this->transfers->list($uid,true),static fn($r)=>$r['expires']>time());
            $stored=array_filter($this->transfers->list($uid),static fn($r)=>$r['expires']>time()&&!in_array($r['state'],['revoked','rejected'],true));
            $reserved=array_sum(array_map(static fn($r)=>$r['kind']==='inbox'?($r['options']['max_bytes']??0):($r['options']['size']??0),$stored));
            $size=$kind==='download'?(int)$node->getSize():$options['max_bytes'];
            if (count($active)>=$p['max_active']||$reserved+$size>$p['max_user_bytes']) { throw new \RuntimeException('Your NextShuttle quota is exhausted'); }
            $id=bin2hex(random_bytes(16));
            if ($kind==='download') {
                $this->policy->file($node->getName(),$size);
                $secret=['token'=>sodium_bin2base64(random_bytes(32),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)];
                $password=$data['password']??'';
                if (!is_string($password)||($p['require_download_password']&&mb_strlen($password)<$p['min_password'])||($password!==''&&(mb_strlen($password)<$p['min_password']||mb_strlen($password)>256))) { throw new \InvalidArgumentException('A separate strong download password is required'); }
                if ($password!=='') { $secret['password']=$password; }
                $options+=['size'=>$size,'etag'=>$node->getEtag()];
            } else {
                $password=$data['password']??'';
                if (!is_string($password)||!preg_match('//u',$password)||mb_strlen($password)<$p['min_password']||mb_strlen($password)>256) { throw new \InvalidArgumentException('Inbox password is shorter than policy allows'); }
                $pair=sodium_crypto_box_keypair();
                $secret=['pair'=>base64_encode($pair),'public'=>sodium_bin2base64(sodium_crypto_box_publickey($pair),SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),'password'=>$password];
                $options['password_length']=mb_strlen($password);
            }
            $this->events->mapOwner($id,$uid); // Before the relay can generate an event.
            $now=time();$row=['id'=>$id,'owner_uid'=>$uid,'kind'=>$kind,'state'=>'queued','relay_id'=>$id,'label'=>$node->getName(),
                'node_id'=>$nodeId,'created'=>$now,'expires'=>$now+$options['ttl'],'attempts'=>0,'retry_after'=>0,'secret'=>$secret,'options'=>$options];
            $this->transfers->insert($row); return Transfers::publicRow($row);
        });
    }
    private function stage(): string {
        $path=$this->temp->getTemporaryFile('.nextshuttle');
        if ($path===false) { throw new \RuntimeException('Private staging is unavailable'); } chmod($path,0600); return $path;
    }
    private function report(string $kind,string $id,?string $parent=null): void {
        $this->events->queueReport($kind,$id,$parent);
    }
    public function revoke(string $uid,string $id): void {
        $this->locked($id,function() use ($uid,$id): void {
            $row=$this->transfers->get($id,$uid); $this->transfers->update($id,['state'=>'revoking']);
            $this->relay->revoke($row['kind']==='download'?'downloads':'inboxes',$id);
            $this->transfers->update($id,['state'=>'revoked']);
        });
    }
    public function retry(string $uid,string $id): void {
        $this->locked($id,function() use ($uid,$id): void {
            $row=$this->transfers->get($id,$uid); $this->policy->user($uid);
            if (!in_array($row['state'],['retry','queued'],true)||$row['expires']<=time()) { throw new \RuntimeException('This transfer cannot be retried'); }
            $this->transfers->update($id,['state'=>'queued','retry_after'=>0]);
        });
    }
    public function rotate(string $uid,string $id,#[\SensitiveParameter] string $password): void {
        $this->locked($id,function() use ($uid,$id,$password): void {
            $row=$this->transfers->get($id,$uid); $this->policy->user($uid);
            if ($row['kind']!=='inbox'||$row['state']!=='ready'||mb_strlen($password)<$this->policy->get()['min_password']||mb_strlen($password)>256) { throw new \InvalidArgumentException('Invalid inbox password change'); }
            $this->relay->call('inboxes/'.$id.'/password',['password'=>$password]);
            $options=$row['options'];$options['password_length']=mb_strlen($password);$this->transfers->update($id,['options'=>$options]);
        });
    }
    public function synchronize(): void {
        try { $this->events->flushReports($this->relay); } catch (\Throwable $e) {}
        try {
            $health=$this->relay->health();if (($health['ready']??false)!==true) { throw new \RuntimeException('Unhealthy scanners'); }
            if ($this->config->getAppValue('nextshuttle','scanner_health')==='unavailable') { $this->events->queueReport('scanner_recovered'); }
            $this->config->setAppValue('nextshuttle','scanner_health','ready');
            $this->config->setAppValue('nextshuttle','scanner_health_details',json_encode($health,JSON_THROW_ON_ERROR));
        } catch (\Throwable $e) {
            if ($this->config->getAppValue('nextshuttle','scanner_health')!=='unavailable') { $this->events->queueReport('scan_unavailable'); }
            $this->config->setAppValue('nextshuttle','scanner_health','unavailable');
        }
        $this->config->setAppValue('nextshuttle','scanner_health_checked',(string)time());
        $remote=null;
        try {
            $listing=$this->relay->listing('transfers');$remote=[];
            foreach (['downloads','inboxes'] as $kind) { foreach ($listing[$kind]??[] as $item) { if (is_string($item['id']??null)) { $remote[$item['id']]=$item; } } }
        } catch (\Throwable $e) {}
        foreach ($this->transfers->list(null,true) as $row) {
            if ($row['retry_after']>time()) { continue; }
            if ($row['state']==='ready'&&$remote!==null&&$row['expires']>time()) {
                $item=$remote[$row['id']]??null;
                if ($item===null||($item['revoked']??false)||in_array($item['state']??'',['revoked','failed'],true)) { $this->transfers->update($row['id'],['state'=>'revoked']);continue; }
                if ($row['kind']==='download'&&($item['uses']??0)>=($item['max_uses']??1)) { $this->transfers->update($row['id'],['state'=>'exhausted']);continue; }
                $options=$row['options'];$options['usage']=$row['kind']==='download'?['downloads'=>(int)($item['uses']??0)]:['files'=>(int)($item['used_files']??0),'bytes'=>(int)($item['used_bytes']??0)];
                $this->transfers->update($row['id'],['options'=>$options]);
            }
            try { $this->locked($row['id'],fn()=>$this->process($this->transfers->get($row['id']))); }
            catch (\Throwable $error) { /* Other transfers must still progress. */ }
        }
        try { $uploads=$this->relay->listing('uploads'); } catch (\Throwable $e) { return; }
        foreach (array_slice($uploads,0,100) as $upload) {
            if (!is_array($upload)||!is_string($upload['id']??null)||!is_string($upload['inbox']??null)) { continue; }
            try { $this->locked($upload['inbox'],fn()=>$this->import($upload)); }
            catch (\Throwable $e) { /* Ciphertext stays on the relay for retry. */ }
        }
        try { $this->events->flushReports($this->relay); } catch (\Throwable $e) {}
        $pending=array_filter($this->transfers->list(null,true),static fn($r)=>$r['state']==='revoking');
        $this->config->setAppValue('nextshuttle','needs_reconcile',$pending?'1':'0');
    }
    private function process(array $row): void {
        $id=$row['id'];
        try {
            if ($row['state']==='revoking') { $this->relay->revoke($row['kind']==='download'?'downloads':'inboxes',$id); $this->transfers->update($id,['state'=>'revoked']); return; }
            if ($row['expires']<=time()) { $this->transfers->update($id,['state'=>'expired']); return; }
            try {
                $this->node($row['owner_uid'],$row['node_id'],$row['kind']); $p=$this->policy->get();
                $check=['ttl'=>$row['expires']-$row['created']];
                if ($row['kind']==='download') {
                    $check['max_uses']=$row['options']['max_uses'];$this->policy->file($row['label'],$row['options']['size']);
                    if (($p['require_download_password']&&!isset($row['secret']['password']))||(isset($row['secret']['password'])&&mb_strlen($row['secret']['password'])<$p['min_password'])) { throw new \RuntimeException('Password policy changed'); }
                } else {
                    $check+=['max_files'=>$row['options']['max_files'],'max_bytes'=>$row['options']['max_bytes']];
                    if (($row['options']['password_length']??16)<$p['min_password']) { throw new \RuntimeException('Password policy changed'); }
                }
                $this->policy->options($row['owner_uid'],$row['kind'],$check);
            } catch (\Throwable $e) {
                $this->transfers->update($id,['state'=>'revoking']); $this->relay->revoke($row['kind']==='download'?'downloads':'inboxes',$id); $this->transfers->update($id,['state'=>'revoked']); return;
            }
            if ($row['state']==='ready') { return; }
            $this->transfers->update($id,['state'=>'preparing']);
            if ($row['kind']==='inbox') {
                $this->relay->call('inboxes',['id'=>$id,'expires'=>$row['expires'],'password'=>$row['secret']['password'],
                    'public_key'=>base64_encode(sodium_base642bin($row['secret']['public'],SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING)),
                    'max_bytes'=>$row['options']['max_bytes'],'max_files'=>$row['options']['max_files']]);
                $secret=$row['secret']; unset($secret['password']);
                $this->transfers->update($id,['state'=>'ready','secret'=>$secret]); return;
            }
            $this->prepareDownload($row);
        } catch (ScanRejected $e) {
            try { $this->report($e->getMessage(),$id); $this->relay->revoke('downloads',$id); } catch (\Throwable $ignored) {}
            $this->transfers->update($id,['state'=>'rejected']);
        } catch (\Throwable $e) {
            $attempt=$row['attempts']+1;
            $state=$this->transfers->get($id)['state']==='revoking'?'revoking':'retry';
            $this->transfers->update($id,['state'=>$state,'attempts'=>$attempt,'retry_after'=>time()+min(3600,30*(2**min(7,$attempt)))]);
            if ($attempt===1) { try { $this->report('scan_unavailable',$id); } catch (\Throwable $ignored) {} }
        }
    }
    private function prepareDownload(array $row): void {
        $id=$row['id']; $secret=$row['secret']; $options=$row['options'];
        if (isset($options['cipher_bytes'],$secret['key'])) {
            $existing=$this->relay->call('downloads',['id'=>$id,'access_token'=>$secret['token'],'password'=>$secret['password']??null,'expires'=>$row['expires'],'bytes'=>$options['cipher_bytes'],'max_uses'=>$options['max_uses']]);
            if (($existing['state']??'')==='ready') { $this->transfers->update($id,['state'=>'ready']); return; }
            if (($existing['state']??'')==='writing') { throw new \RuntimeException('Snapshot transfer still finishing'); }
            if (($existing['state']??'')==='failed') { $this->relay->call('downloads/'.$id.'/reset',[]); }
        }
        $plain=$this->stage(); $cipher=$this->stage();
        try {
            $node=$this->node($row['owner_uid'],$row['node_id'],'download');
            if ($node->getEtag()!==$options['etag']) { throw new ScanRejected('content_rejected'); }
            $node->lock(ILockingProvider::LOCK_SHARED);
            try {
                $in=$node->fopen('rb'); $out=fopen($plain,'wb');
                try { $size=stream_copy_to_stream($in,$out,$this->policy->get()['max_file']+1); } finally { fclose($in); fclose($out); }
            } finally { $node->unlock(ILockingProvider::LOCK_SHARED); }
            $this->policy->file($row['label'],$size); $receipt=$this->relay->scan($plain,$row['label']);
            $this->report('scan_clean',$id);
            $in=fopen($plain,'rb'); $out=fopen($cipher,'wb');
            try { $key=FileCrypto::encrypt($in,$out,$row['label'],$size); } finally { fclose($in); fclose($out); }
            $secret['key']=sodium_bin2base64($key,SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            clearstatcache(true,$cipher);$options['cipher_bytes']=filesize($cipher); $options['scan']=$receipt;
            $this->transfers->update($id,['secret'=>$secret,'options'=>$options]);
            $this->relay->call('downloads',['id'=>$id,'access_token'=>$secret['token'],'password'=>$secret['password']??null,'expires'=>$row['expires'],'bytes'=>$options['cipher_bytes'],'max_uses'=>$options['max_uses']]);
            $in=fopen($cipher,'rb'); try { $this->relay->put($id,$in,$options['cipher_bytes']); } finally { if (is_resource($in)) { fclose($in); } }
            $this->transfers->update($id,['state'=>'ready']);
        } finally { @unlink($plain); @unlink($cipher); }
    }
    private function import(array $upload): void {
        $id=Relay::id($upload['id']); $inbox=$this->transfers->get(Relay::id($upload['inbox']));
        if ($inbox['kind']!=='inbox'||!in_array($inbox['state'],['ready','expired'],true)) { return; }
        $folder=$this->node($inbox['owner_uid'],$inbox['node_id'],'inbox');
        $old=$this->transfers->receipt($id);
        if (in_array($old['state']??'',['stored','done'],true)) {
            if ($old['state']==='stored') { $this->report('upload_imported',$id,$inbox['id']);$this->transfers->imported($id,(int)$old['node_id'],'done'); }
            $this->relay->revoke('uploads',$id);return;
        }
        $plain=$this->stage(); $cipher=$this->stage();
        try {
            $out=fopen($cipher,'wb'); try { $this->relay->fetch($id,$out,(int)($upload['bytes']??0)); } finally { fclose($out); }
            $in=fopen($cipher,'rb'); $out=fopen($plain,'wb');
            try { $meta=FileCrypto::decrypt($in,$out,null,base64_decode($inbox['secret']['pair'],true)); }
            catch (\UnexpectedValueException|\SodiumException|\JsonException $e) { throw new ScanRejected('content_rejected'); }
            finally { fclose($in); fclose($out); }
            $this->policy->file($meta['name'],$meta['size']); $receipt=$this->relay->scan($plain,$meta['name']); $this->report('scan_clean',$id,$inbox['id']);
            // Stable, reserved name allows safe reconciliation if the process dies after file creation.
            $name='shuttle-'.$id.'-'.mb_strcut($meta['name'],0,190,'UTF-8');
            $plan=$this->transfers->plan($id,$inbox['id'],$name,$receipt['sha256']);
            $folder=$this->node($inbox['owner_uid'],$inbox['node_id'],'inbox');
            $folder->lock(ILockingProvider::LOCK_EXCLUSIVE);
            try {
            if ($folder->nodeExists($plan['name'])) {
                $file=$folder->get($plan['name']);
                if (!$file instanceof File) { throw new \RuntimeException('Import name conflict'); }
                $stream=$file->fopen('rb'); try { $hash=hash_init('sha256'); hash_update_stream($hash,$stream); $actual=hash_final($hash); } finally { fclose($stream); }
                if ($actual!==$receipt['sha256']) { throw new \RuntimeException('Import conflict requires review'); }
            } else {
                if ($folder->getFreeSpace()>=0&&$folder->getFreeSpace()<$meta['size']) { throw new \RuntimeException('Nextcloud quota exhausted'); }
                $stream=fopen($plain,'rb'); try { $file=$folder->newFile($plan['name'],$stream); } finally { fclose($stream); }
            }
            $this->transfers->imported($id,(int)$file->getId());
            } finally { $folder->unlock(ILockingProvider::LOCK_EXCLUSIVE); }
            $this->report('upload_imported',$id,$inbox['id']);
            $this->transfers->imported($id,(int)$file->getId(),'done');$this->relay->revoke('uploads',$id);
        } catch (ScanRejected $e) {
            $this->report($e->getMessage(),$id,$inbox['id']); $this->relay->revoke('uploads',$id);
        } catch (\Throwable $e) { $this->report('scan_unavailable',$id,$inbox['id']); }
        finally { @unlink($plain); @unlink($cipher); }
    }
}
