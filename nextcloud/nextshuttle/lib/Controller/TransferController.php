<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Controller;
use OCA\NextShuttle\Service\Shuttle;
use OCA\NextShuttle\Service\Transfers;
use OCA\NextShuttle\Service\Policy;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;
use OCP\IUserSession;
class TransferController extends Controller {
    private function json(mixed $data,int $status=200): JSONResponse {
        $response=new JSONResponse($data,$status);
        $response->addHeader('Cache-Control','no-store');
        $response->addHeader('Pragma','no-cache');
        return $response;
    }
    public function __construct(IRequest $request,private IUserSession $session,private Shuttle $shuttle,private Transfers $transfers,private Policy $policy) { parent::__construct('nextshuttle',$request); }
    private function uid(): string {
        $user=$this->session->getUser(); if ($user===null) { throw new \RuntimeException('Authentication required'); } return $user->getUID();
    }
    private function safely(callable $work): JSONResponse {
        try { return $this->json($work()); }
        catch (\InvalidArgumentException $e) { return $this->json(['error'=>$e->getMessage()],400); }
        catch (\OCP\Files\NotFoundException $e) { return $this->json(['error'=>'Transfer not found'],404); }
        catch (\OCP\Files\NotPermittedException $e) { return $this->json(['error'=>'This transfer is not permitted'],403); }
        catch (\Throwable $e) { return $this->json(['error'=>'Operation unavailable. Check the transfer status and administrator settings.'],503); }
    }
    #[NoAdminRequired] #[NoCSRFRequired]
    public function index(): JSONResponse { return $this->safely(fn()=>['transfers'=>array_map(Transfers::publicRow(...),$this->transfers->list($this->uid())),'policy'=>$this->policy->get()]); }
    #[NoAdminRequired]
    public function create(string $kind,int $nodeId,#[\SensitiveParameter] array $options=[]): JSONResponse { return $this->safely(fn()=>$this->shuttle->create($this->uid(),$kind,$nodeId,$options)); }
    #[NoAdminRequired]
    public function revoke(string $id): JSONResponse { return $this->safely(function() use($id) { $this->shuttle->revoke($this->uid(),$id); return ['ok'=>true]; }); }
    #[NoAdminRequired]
    public function retry(string $id): JSONResponse { return $this->safely(function() use($id) { $this->shuttle->retry($this->uid(),$id); return ['ok'=>true]; }); }
    #[NoAdminRequired]
    public function password(string $id,#[\SensitiveParameter] string $password): JSONResponse { return $this->safely(function() use($id,$password) { $this->shuttle->rotate($this->uid(),$id,$password); return ['ok'=>true]; }); }
}
