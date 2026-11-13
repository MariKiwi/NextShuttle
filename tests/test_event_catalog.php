<?php
declare(strict_types=1);
require __DIR__ . '/../nextcloud/nextshuttle/lib/Service/EventCatalog.php';
use OCA\NextShuttle\Service\EventCatalog;

$valid = ['sequence' => 1, 'occurred' => 1794560000, 'kind' => 'malware_detected',
    'severity' => 'critical', 'object_id' => str_repeat('a', 32), 'parent_id' => null];
EventCatalog::validate($valid);
foreach (['sequence' => '1', 'occurred' => -1, 'kind' => 'untrusted-secret',
    'severity' => 'unknown', 'object_id' => '../sensitive-path'] as $key => $value) {
    $case = $valid;
    $case[$key] = $value;
    try {
        EventCatalog::validate($case);
        throw new RuntimeException('Malformed event was accepted: ' . $key);
    } catch (UnexpectedValueException $expected) {}
}
echo "Event catalog validation passed.\n";
