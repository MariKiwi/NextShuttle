<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Controller;

use OCA\NextShuttle\Service\Events;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IRequest;
use OCP\IUserSession;

class PageController extends Controller {
    public function __construct(IRequest $request, private IUserSession $session, private Events $events,private \OCP\IConfig $config) {
        parent::__construct('nextshuttle', $request);
    }
    #[NoAdminRequired]
    #[NoCSRFRequired]
    public function index(): TemplateResponse {
        \OCP\Util::addScript('nextshuttle','main');
        \OCP\Util::addStyle('nextshuttle','main');
        $user = $this->session->getUser();
        if ($user === null) { throw new \RuntimeException('Authentication required'); }
        $actor=substr(hash_hmac('sha256','nextshuttle-actor:'.$user->getUID(),$this->config->getSystemValueString('secret')),0,32);
        $this->events->mapOwner($actor,$user->getUID());$this->events->queueReport('page_accessed',$actor);
        return new TemplateResponse('nextshuttle', 'events', ['events' => $this->events->visible($user->getUID())]);
    }
}
