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
    public function __construct(IRequest $request, private IUserSession $session, private Events $events) {
        parent::__construct('nextshuttle', $request);
    }
    #[NoAdminRequired]
    #[NoCSRFRequired]
    public function index(): TemplateResponse {
        $user = $this->session->getUser();
        if ($user === null) { throw new \RuntimeException('Authentication required'); }
        return new TemplateResponse('nextshuttle', 'events', ['events' => $this->events->visible($user->getUID())]);
    }
}
