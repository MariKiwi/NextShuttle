<?php
declare(strict_types=1);
define('OC_CONSOLE',true);
require '/var/www/html/lib/base.php';
\OC_App::loadApps();
if (($argv[1]??'')==='worker') { \OC::$server->get(\OCA\NextShuttle\Service\Shuttle::class)->synchronize();exit(0); }
function work(): void {
    $process=proc_open([PHP_BINARY,__FILE__,'worker'],[0=>['file','/dev/null','r'],1=>STDOUT,2=>STDERR],$pipes);
    if (!is_resource($process)||proc_close($process)!==0) { throw new RuntimeException('Unattended transfer worker failed'); }
}
function check(bool $condition,string $message): void { if (!$condition) { throw new RuntimeException($message); } }
$server=\OC::$server;
$users=$server->get(\OCP\IUserManager::class);$groups=$server->get(\OCP\IGroupManager::class);
foreach (['alice','bob','second-admin'] as $uid) { if ($users->get($uid)===null) { $users->createUser($uid,'ephemeral-ci-password-246810'); } }
$groups->get('admin')->addUser($users->get('second-admin'));
$config=$server->get(\OCP\IConfig::class);
$config->setAppValue('core','shareapi_allow_public_upload','yes');
$config->setAppValue('core','shareapi_allow_links','yes');
$config->setSystemValue('nextshuttle_ca_file','/tmp/ci-ca.crt');
$crypto=$server->get(\OCP\Security\ICrypto::class);
$config->setAppValue('nextshuttle','service_token',$crypto->encrypt(str_repeat('r',64)));
$config->setAppValue('nextshuttle','scanner_token',$crypto->encrypt(str_repeat('s',64)));
$session=$server->get(\OCP\IUserSession::class);$session->setUser($users->get('alice'));
\OC_Util::setupFS('alice');
$root=$server->get(\OCP\Files\IRootFolder::class);$folder=$root->getUserFolder('alice');
$shuttle=$server->get(\OCA\NextShuttle\Service\Shuttle::class);
$transfers=$server->get(\OCA\NextShuttle\Service\Transfers::class);
$events=$server->get(\OCA\NextShuttle\Service\Events::class);
$file=$folder->newFile('outgoing.txt','ordinary outgoing CI content');
$download=$shuttle->create('alice','download',(int)$file->getId(),['ttl'=>3600]);
check(!isset($download['secret']),'Public row exposed secret storage');
work();$ready=$transfers->get($download['id'],'alice');
check($ready['state']==='ready','Outgoing transfer did not become ready');
try { $transfers->get($download['id'],'bob');throw new RuntimeException('Owner isolation bypass'); } catch (\OCP\Files\NotFoundException $expected) {}
function publicRequest(string $method,string $path,string $body,array $headers=[]): string {
    $raw=file_get_contents('http://relay-public:8080/nextshuttle/api/v1/'.$path,false,stream_context_create(['http'=>[
        'method'=>$method,'content'=>$body,'header'=>implode("\r\n",$headers),'ignore_errors'=>false,'timeout'=>30]]));
    if ($raw===false) { throw new RuntimeException('Public API request failed'); } return $raw;
}
$cipher=publicRequest('POST','downloads/'.$ready['id'].'/fetch','',['Authorization: Bearer '.$ready['secret']['token']]);
$in=tmpfile();$out=tmpfile();fwrite($in,$cipher);rewind($in);
$meta=\OCA\NextShuttle\Service\FileCrypto::decrypt($in,$out,sodium_base642bin($ready['secret']['key'],SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));
rewind($out);check(stream_get_contents($out)==='ordinary outgoing CI content','Public download did not decrypt');fclose($in);fclose($out);
$destination=$folder->newFolder('Received');
$inbox=$shuttle->create('alice','inbox',(int)$destination->getId(),['ttl'=>3600,'password'=>'a long static ci password','max_files'=>5,'max_bytes'=>1048576]);
work();$inboxRow=$transfers->get($inbox['id'],'alice');check($inboxRow['state']==='ready','Inbox not ready');
function uploadFixture(array $inbox,string $content,string $name): string {
    $in=tmpfile();$out=tmpfile();fwrite($in,$content);rewind($in);
    \OCA\NextShuttle\Service\FileCrypto::encrypt($in,$out,$name,strlen($content),sodium_base642bin($inbox['secret']['public'],SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING));
    rewind($out);$blob=stream_get_contents($out);fclose($in);fclose($out);
    $reservation=json_decode(publicRequest('POST','inboxes/'.$inbox['id'].'/uploads',json_encode(['password'=>'a long static ci password','bytes'=>strlen($blob)]),['Content-Type: application/json']),true,16,JSON_THROW_ON_ERROR);
    publicRequest('PUT','uploads/'.$reservation['id'].'/blob',$blob,['Authorization: Bearer '.$reservation['upload_token'],'Content-Type: application/octet-stream']);return $reservation['id'];
}
$upload=uploadFixture($inboxRow,'ordinary incoming CI content','incoming.txt');
work();$receipt=$transfers->receipt($upload);check($receipt!==null&&$receipt['state']==='done','Upload was not imported');
$imported=$destination->get($receipt['name']);check($imported->getContent()==='ordinary incoming CI content','Imported bytes differ');
$count=count($destination->getDirectoryListing());work();check(count($destination->getDirectoryListing())===$count,'Retry duplicated an import');
uploadFixture($inboxRow,'reject-this-ci-file','blocked.txt');work();check(count($destination->getDirectoryListing())===$count,'Rejected upload was imported');
$poll=$server->get(\OCA\NextShuttle\BackgroundJob\PollEvents::class);$run=new ReflectionMethod($poll,'run');$run->invoke($poll,null);
check(count($events->visible('alice'))>0,'Owner audit events missing');check(count($events->visible('bob'))===0,'Unrelated user can read audit events');
$db=$server->get(\OCP\IDBConnection::class);
foreach (['admin','second-admin','alice'] as $uid) {
    $q=$db->getQueryBuilder();$q->select($q->func()->count('*'))->from('notifications')->where($q->expr()->eq('app',$q->createNamedParameter('nextshuttle')))->andWhere($q->expr()->eq('user',$q->createNamedParameter($uid)));
    $r=$q->executeQuery();check((int)$r->fetchOne()>0,'Notification missing for '.$uid);$r->closeCursor();
}
$shuttle->revoke('alice',$inbox['id']);check($transfers->get($inbox['id'],'alice')['state']==='revoked','Inbox revocation failed');
echo "Nextcloud 35.0.2 integration: outgoing/incoming encryption, scan transport, import retries, rejection, owner isolation and admin/owner notifications passed.\n";
