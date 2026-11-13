<?php
declare(strict_types=1);
namespace OCA\NextShuttle\AppInfo;

use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IRegistrationContext;

class Application extends App implements IBootstrap {
    public function __construct(array $urlParams = []) { parent::__construct('nextshuttle', $urlParams); }
    public function register(IRegistrationContext $context): void {
        $context->registerNotifierService(\OCA\NextShuttle\Notification\Notifier::class);
        $context->registerEventListener(\OCA\Files\Event\LoadAdditionalScriptsEvent::class,\OCA\NextShuttle\Listener\FilesListener::class);
    }
    public function boot(IBootContext $context): void {}
}
