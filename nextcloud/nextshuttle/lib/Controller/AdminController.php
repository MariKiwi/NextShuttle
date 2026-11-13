<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Controller;
use OCA\NextShuttle\Service\Policy;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\ICrypto;
class AdminController extends Controller {
    public function __construct(IRequest $request,private Policy $policy,private IConfig $config,private ICrypto $crypto,private \OCA\NextShuttle\Service\Events $events,private \OCP\IDBConnection $db) { parent::__construct('nextshuttle',$request); }
    // Default AppFramework middleware requires an authenticated global admin + CSRF.
    public function save(array $policy=[],#[\SensitiveParameter] string $serviceToken='',#[\SensitiveParameter] string $scannerToken=''): JSONResponse {
        foreach ([$serviceToken,$scannerToken] as $token) {
            if ($token!==''&&!preg_match('/^[A-Za-z0-9_-]{43,128}$/D',$token)) { return new JSONResponse(['error'=>'Invalid service credential'],400); }
        }
        $this->db->beginTransaction();
        try {
        $this->policy->save($policy);
        foreach (['service_token'=>$serviceToken,'scanner_token'=>$scannerToken] as $key=>$value) {
            if ($value!=='') { $this->config->setAppValue('nextshuttle',$key,$this->crypto->encrypt($value)); }
        }
        $this->config->setAppValue('nextshuttle','needs_reconcile','1');
        $this->events->queueReport('policy_changed');
        if ($serviceToken!==''||$scannerToken!=='') { $this->events->queueReport('credentials_rotated'); }
        $this->db->commit();
        } catch (\InvalidArgumentException $e) { $this->db->rollBack();return new JSONResponse(['error'=>$e->getMessage()],400); }
        catch (\Throwable $e) { $this->db->rollBack();return new JSONResponse(['error'=>'Settings could not be saved with their audit record'],503); }
        return new JSONResponse(['ok'=>true,'message'=>'Saved. Existing transfers are rechecked by the background job.']);
    }
}
