<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;

use OCP\Http\Client\IClientService;
use OCP\IConfig;
use OCP\Security\ICrypto;

class Relay {
    public function __construct(private IClientService $clients, private IConfig $config, private ICrypto $crypto) {}
    public function call(string $path, array $body): array {
        if (!in_array($path, ['events/read', 'events/ack'], true)) {
            throw new \InvalidArgumentException('Unsupported bridge operation');
        }
        $base = $this->config->getAppValue('nextshuttle', 'relay_url', 'https://shuttle.helios.lan/');
        if ($base !== 'https://shuttle.helios.lan/') {
            throw new \RuntimeException('Private relay URL is not permitted');
        }
        $encrypted = $this->config->getAppValue('nextshuttle', 'service_token');
        if ($encrypted === '') { throw new \RuntimeException('Configure NextShuttle first'); }
        $options = [
            'json' => $body,
            'headers' => ['Authorization' => 'Bearer ' . $this->crypto->decrypt($encrypted)],
            'timeout' => 15,
            'read_timeout' => 15,
            'allow_redirects' => false,
            'nextcloud' => ['allow_local_address' => true],
            'stream' => true,
            // Inherit Nextcloud's verified CA bundle, including imported private CAs.
        ];
        // Optional mTLS identity paths come from trusted server configuration only.
        foreach (['cert' => 'nextshuttle_client_cert', 'ssl_key' => 'nextshuttle_client_key'] as $option => $setting) {
            $value = $this->config->getSystemValueString($setting, '');
            if ($value !== '') { $options[$option] = $value; }
        }
        $response = $this->clients->newClient()->post($base . 'api/v1/' . $path, $options);
        if ($response->getStatusCode() !== 200) { throw new \RuntimeException('Relay request failed'); }
        $body = $response->getBody();
        if (!is_resource($body)) { throw new \UnexpectedValueException('Expected a streaming response'); }
        try {
            stream_set_timeout($body, 15);
            $raw = stream_get_contents($body, 1048577);
            if ($raw === false || strlen($raw) > 1048576 || (stream_get_meta_data($body)['timed_out'] ?? false)) {
                throw new \UnexpectedValueException('Relay response limit exceeded');
            }
        } finally { fclose($body); }
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($data)) { throw new \UnexpectedValueException('Invalid relay response'); }
        return $data;
    }
}
