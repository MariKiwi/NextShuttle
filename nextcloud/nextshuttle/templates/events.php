<?php
declare(strict_types=1);
/** @var array $_ */
use OCA\NextShuttle\Service\EventCatalog;
?>
<nav id="app-navigation" class="ns-navigation" aria-label="NextShuttle"><div class="ns-nav-brand">NextShuttle</div><ul><li class="active"><a href="#ns-workspace">All transfers</a></li><li><a href="#ns-security">Security events</a></li><li><a href="<?php p(\OC::$server->get(\OCP\IURLGenerator::class)->linkToRoute('files.view.index')); ?>">Open Files</a></li></ul><p>To share a file or receive uploads, open its sharing options in Files.</p><small>NextShuttle 0.3.2</small></nav><div id="app-content"><div id="app-content-wrapper" class="ns-area">
    <div class="ns-header" id="ns-workspace"><div><p class="ns-eyebrow">NEXTSHUTTLE · 0.3.2</p><h1>Your transfers</h1><p>Manage shared files and upload inboxes from your Nextcloud.</p></div><a class="ns-files-link" href="<?php p(\OC::$server->get(\OCP\IURLGenerator::class)->linkToRoute('files.view.index')); ?>">Open Files</a></div>
    <div class="ns-overview"><div><strong id="ns-ready">0</strong><span>Ready to share</span></div><div><strong id="ns-inboxes">0</strong><span>Open upload inboxes</span></div><div><strong id="ns-total">0</strong><span>Your transfers</span></div></div>
    <section class="ns-transfer-section"><div class="ns-toolbar"><label class="ns-search-label">Find a transfer<input id="ns-search" type="search" placeholder="Search filenames or folders"></label><label>Show<select id="ns-filter"><option value="all">All transfers</option><option value="download">Shared files</option><option value="inbox">Upload inboxes</option></select></label><button id="ns-refresh">Refresh</button><span id="ns-refresh-status" role="status"></span></div>
    <div id="ns-transfers" aria-live="polite">Loading your transfers…</div>
    </section><details class="ns-events" id="ns-security"><summary>Recent security events</summary><p>Latest 100 events visible to your account.</p><div class="ns-table-scroll">
    <table><thead><tr><th>Event</th><th>UTC time</th><th>Severity</th><th>Description</th><th>Visitor IP</th><th>Estimated country</th><th>Transfer reference</th></tr></thead><tbody>
    <?php foreach ($_['events'] as $event): ?>
        <tr>
            <td><?php p($event['sequence']); ?></td>
            <td><?php p(gmdate('Y-m-d H:i:s', (int)$event['occurred'])); ?></td>
            <td><?php p($event['severity']); ?></td>
            <td><?php p(EventCatalog::LABELS[$event['kind']] ?? 'Unknown event'); ?></td>
            <td><?php p($event['client_ip']??'—'); ?><?php if (($event['ip_source']??null)==='peer'): ?><small class="ns-hint"> · Observed peer</small><?php endif; ?></td><td><?php p(isset($event['country'])?(class_exists('Locale')?\Locale::getDisplayRegion('und_'.$event['country'],'en'):$event['country']):(($event['country_status']??'')==='private_or_reserved'?'Private / reserved address':'Unknown')); ?></td>
            <td><?php p($event['parent_id'] ?? $event['object_id'] ?? 'Unidentified'); ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody></table></div>
    <p class="ns-hint">Country is an estimate for the observed address, which may belong to a VPN or proxy. <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a>.</p>
    </details>
</div></div>
