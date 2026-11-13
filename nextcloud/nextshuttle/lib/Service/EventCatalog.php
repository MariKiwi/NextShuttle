<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;

class EventCatalog {
    public const LABELS = [
        'download_created' => 'A download was created',
        'download_ready' => 'A download is ready',
        'download_claimed' => 'A download was authorized',
        'download_served' => 'Download bytes were sent',
        'download_interrupted' => 'A download was interrupted',
        'inbox_created' => 'An upload inbox was created',
        'upload_reserved' => 'An upload was started',
        'upload_received' => 'An encrypted upload was received (not yet cleared)',
        'upload_interrupted' => 'An upload was interrupted',
        'transfer_revoked' => 'A transfer was revoked',
        'password_rotated' => 'An inbox password was changed',
        'transfer_expired' => 'A transfer expired',
        'page_accessed' => 'The public shuttle page was accessed',
        'access_denied' => 'Access was denied (invalid code, permission or unavailable transfer)',
        'wrong_code' => 'An incorrect transfer code or upload password was entered',
        'request_rejected' => 'A request was rejected',
        'rate_limited' => 'Requests were rate limited',
        'service_error' => 'A relay error occurred',
        'malware_detected' => 'A dangerous upload was blocked',
        'content_rejected' => 'An upload failed content validation',
        'scan_unavailable' => 'Upload scanning is unavailable; import remains blocked',
        'upload_imported' => 'A cleared upload was imported',
        'scan_clean' => 'Both scanners cleared an upload',
    ];
    public static function validate(array $event): void {
        if (!is_int($event['sequence'] ?? null) || $event['sequence'] < 1
            || !is_int($event['occurred'] ?? null) || $event['occurred'] < 0
            || !isset(self::LABELS[$event['kind'] ?? ''])
            || !in_array($event['severity'] ?? '', ['info', 'warning', 'critical'], true)) {
            throw new \UnexpectedValueException('Invalid relay event');
        }
        foreach (['object_id', 'parent_id'] as $key) {
            if (($event[$key] ?? null) !== null && (!is_string($event[$key]) || !preg_match('/^[a-f0-9]{32}$/D', $event[$key]))) {
                throw new \UnexpectedValueException('Invalid event object');
            }
        }
    }
}
