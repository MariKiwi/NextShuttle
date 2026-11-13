<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\IConfig;
use OCP\Security\ICrypto;
class Relay {
    public function __construct(private IClientService $clients, private IConfig $config, private ICrypto $crypto) {}
    public static function id(string $id): string {
        if (!preg_match('/^[a-f0-9]{32}$/D',$id)) { throw new \InvalidArgumentException('Invalid transfer ID'); } return $id;
    }
    private function request(string $method,string $path,#[\SensitiveParameter] array $options,bool $scanner=false): IResponse {
        $base=$this->config->getAppValue('nextshuttle','relay_url','https://shuttle.helios.lan/');
        if ($base!=='https://shuttle.helios.lan/') { throw new \RuntimeException('Private relay URL not permitted'); }
        $secret=$this->config->getAppValue('nextshuttle',$scanner?'scanner_token':'service_token');
        if ($secret==='') { throw new \RuntimeException('Configure NextShuttle credentials first'); }
        $options['headers']['Authorization']='Bearer '.$this->crypto->decrypt($secret);
        $options+=['timeout'=>300,'read_timeout'=>180,'allow_redirects'=>false,'nextcloud'=>['allow_local_address'=>true],'stream'=>true,'http_errors'=>false];
        // Use Nextcloud's verified CA bundle, including imported private CAs.
        foreach (['cert'=>'nextshuttle_client_cert','ssl_key'=>'nextshuttle_client_key','verify'=>'nextshuttle_ca_file'] as $option=>$setting) {
            $value=$this->config->getSystemValueString($setting,''); if ($value!=='') { $options[$option]=$value; }
        }
        return $this->clients->newClient()->request($method,$base.($scanner?'ingestion/v1/':'api/v1/').$path,$options);
    }
    private function json(IResponse $response,array $accepted=[200,201]): array {
        $stream=$response->getBody(); if (!is_resource($stream)) { throw new \UnexpectedValueException('Invalid service stream'); }
        try {
            stream_set_timeout($stream,180); $raw=stream_get_contents($stream,4194305);
            if ($raw===false||strlen($raw)>4194304||(stream_get_meta_data($stream)['timed_out']??false)) { throw new \RuntimeException('Service response limit'); }
        } finally { if (is_resource($stream)) { fclose($stream); } }
        if (!in_array($response->getStatusCode(),$accepted,true)) { throw new \RuntimeException('Private service request failed'); }
        $data=json_decode($raw,true,32,JSON_THROW_ON_ERROR); if (!is_array($data)) { throw new \UnexpectedValueException('Invalid service response'); } return $data;
    }
    public function call(string $path,#[\SensitiveParameter] array $body): array {
        if (!preg_match('~^(events/(read|ack|report)|downloads|inboxes|cleanup|inboxes/[a-f0-9]{32}/password|downloads/[a-f0-9]{32}/reset)$~D',$path)) { throw new \InvalidArgumentException('Unsupported operation'); }
        return $this->json($this->request('POST',$path,['json'=>$body]));
    }
    public function listing(string $kind): array {
        if (!in_array($kind,['uploads','transfers'],true)) { throw new \InvalidArgumentException('Unsupported list'); }
        return $this->json($this->request('GET',$kind,[]));
    }
    public function health(): array { return $this->json($this->request('GET','health',['timeout'=>35],true)); }
    public function put(string $id,$stream,int $length): void {
        $this->json($this->request('PUT','downloads/'.self::id($id).'/blob',['body'=>$stream,'headers'=>['Content-Length'=>(string)$length,'Content-Type'=>'application/octet-stream']]));
    }
    public function fetch(string $id,$out,int $expected): void {
        if ($expected<1||$expected>FileCrypto::MAX_CIPHER) { throw new \UnexpectedValueException('Invalid ciphertext size'); }
        $response=$this->request('GET','uploads/'.self::id($id).'/blob',[]); $in=$response->getBody();
        if (!is_resource($in)) { throw new \RuntimeException('Invalid upload stream'); }
        try {
            if ($response->getStatusCode()!==200) { throw new \RuntimeException('Retrieval unavailable'); }
            if (stream_copy_to_stream($in,$out,$expected+1)!==$expected||!feof($in)) { throw new \UnexpectedValueException('Ciphertext size mismatch'); }
        } finally { fclose($in); }
    }
    public function revoke(string $kind,string $id): void {
        if (!in_array($kind,['downloads','inboxes','uploads'],true)) { throw new \InvalidArgumentException('Invalid transfer type'); }
        $this->json($this->request('DELETE',$kind.'/'.self::id($id),[]));
    }
    public function scan(string $path,string $filename): array {
        clearstatcache(true,$path);
        $size=filesize($path); $hash=hash_file('sha256',$path); $stream=fopen($path,'rb');
        if ($size<1||$size>FileCrypto::MAX_PLAIN||$stream===false) { throw new \RuntimeException('Invalid staging input'); }
        try {
            $response=$this->request('POST','scan',['body'=>$stream,'headers'=>['Content-Length'=>(string)$size,'Content-Type'=>'application/octet-stream','X-NextShuttle-Name'=>base64_encode(FileCrypto::safeName($filename))]],true);
            $receipt=$this->json($response,[200,422]);
            if ($response->getStatusCode()===422) { throw new ScanRejected(($receipt['reason']??'')==='malware_detected'?'malware_detected':'content_rejected'); }
        } finally { if (is_resource($stream)) { fclose($stream); } }
        $engines=array_column($receipt['verdicts']??[],'engine'); sort($engines);
        if ($engines!==['clamav','lmd-native']||($receipt['sha256']??'')!==$hash||($receipt['bytes']??0)!==$size||hash_file('sha256',$path)!==$hash) { throw new \RuntimeException('Invalid scanner approval'); }
        return $receipt;
    }
}
