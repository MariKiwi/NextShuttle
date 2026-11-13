<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Settings;

use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\Settings\ISettings;

class Admin implements ISettings {
    public function __construct(private IConfig $config,private \OCA\NextShuttle\Service\Policy $policy) {}
    public function getForm(): TemplateResponse {
        \OCP\Util::addScript('nextshuttle','main'); \OCP\Util::addStyle('nextshuttle','main');
        return new TemplateResponse('nextshuttle', 'admin', [
            'configured' => $this->config->getAppValue('nextshuttle', 'service_token') !== '',
            'last_sync' => $this->config->getAppValue('nextshuttle', 'last_event_sync', 'Not yet synchronized'),
            'cursor' => $this->config->getAppValue('nextshuttle', 'event_cursor', '0'),
            'scanner_configured'=>$this->config->getAppValue('nextshuttle','scanner_token')!=='',
            'policy'=>$this->policy->get(),
            'scanner_health'=>$this->config->getAppValue('nextshuttle','scanner_health','Not checked'),
            'scanner_health_checked'=>$this->config->getAppValue('nextshuttle','scanner_health_checked','Not checked'),
            'needs_reconcile'=>$this->config->getAppValue('nextshuttle','needs_reconcile','0')==='1',
        ]);
    }
    public function getSection(): string { return 'additional'; }
    public function getPriority(): int { return 50; }
}
