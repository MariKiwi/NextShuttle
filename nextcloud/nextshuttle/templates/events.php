<?php
declare(strict_types=1);
/** @var array $_ */
use OCA\NextShuttle\Service\EventCatalog;
?>
<div id="app-content"><div id="app-content-wrapper">
    <h2>NextShuttle events</h2>
    <p>Development build. Latest 100 events visible to your account. File transfers are not yet available here.</p>
    <table><thead><tr><th>Event</th><th>UTC time</th><th>Severity</th><th>Description</th><th>Transfer reference</th></tr></thead><tbody>
    <?php foreach ($_['events'] as $event): ?>
        <tr>
            <td><?php p($event['sequence']); ?></td>
            <td><?php p(gmdate('Y-m-d H:i:s', (int)$event['occurred'])); ?></td>
            <td><?php p($event['severity']); ?></td>
            <td><?php p(EventCatalog::LABELS[$event['kind']] ?? 'Unknown event'); ?></td>
            <td><?php p($event['parent_id'] ?? $event['object_id'] ?? 'Unidentified'); ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody></table>
</div></div>
