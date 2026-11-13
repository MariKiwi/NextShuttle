<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Settings;

use OCP\AppFramework\Http\TemplateResponse;
use OCP\IConfig;
use OCP\Settings\ISettings;

class Admin implements ISettings {
    public function __construct(private IConfig $config) {}
    public function getForm(): TemplateResponse {
        return new TemplateResponse('nextshuttle', 'admin', [
            'configured' => $this->config->getAppValue('nextshuttle', 'service_token') !== '',
            'last_sync' => $this->config->getAppValue('nextshuttle', 'last_event_sync', 'Not yet synchronized'),
            'cursor' => $this->config->getAppValue('nextshuttle', 'event_cursor', '0'),
        ]);
    }
    public function getSection(): string { return 'additional'; }
    public function getPriority(): int { return 50; }
}
