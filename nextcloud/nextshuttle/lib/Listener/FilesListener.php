<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Listener;
use OCA\Files\Event\LoadAdditionalScriptsEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Util;
class FilesListener implements IEventListener {
    public function handle(Event $event): void {
        if ($event instanceof LoadAdditionalScriptsEvent) { Util::addScript('nextshuttle','files'); Util::addStyle('nextshuttle','main'); }
    }
}
