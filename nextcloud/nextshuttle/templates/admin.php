<?php
declare(strict_types=1);
/** @var array $_ */
?>
<div class="section">
    <h2>NextShuttle</h2>
    <p>Private relay: https://shuttle.helios.lan/</p>
    <p>Event bridge configured: <?php p($_['configured'] ? 'Yes' : 'No'); ?></p>
    <p>Last successful collection (Unix timestamp): <?php p($_['last_sync']); ?></p>
    <p>Collected through event: <?php p($_['cursor']); ?></p>
    <p>Private scanner configured: <?php p($_['scanner_configured']?'Yes':'No'); ?></p>
    <p>Scanner health: <?php p($_['scanner_health']); ?> · last checked <?php p($_['scanner_health_checked']); ?></p>
    <?php if ($_['needs_reconcile']): ?><p>Policy reconciliation is pending.</p><?php endif; ?>
    <form id="ns-policy">
    <?php foreach (['max_ttl'=>'Maximum lifetime (seconds)','default_ttl'=>'Default lifetime (seconds)',
        'max_file'=>'Maximum file size (bytes, up to 32 MiB)','max_active'=>'Active transfers per user',
        'max_user_bytes'=>'Reserved bytes per user','max_downloads'=>'Downloads per share',
        'max_inbox_files'=>'Files per inbox','max_inbox_bytes'=>'Total bytes per inbox','min_password'=>'Minimum password characters (16 to 128)'] as $key=>$label): ?>
        <label><?php p($label); ?><input type="number" name="<?php p($key); ?>" value="<?php p($_['policy'][$key]); ?>" min="1" required></label>
    <?php endforeach; ?>
        <label>Eligible group IDs (comma separated; empty allows all eligible Nextcloud users)<input name="groups" value="<?php p(implode(',',$_['policy']['groups'])); ?>"></label>
        <label>Allowed file extensions (comma separated)<input name="types" value="<?php p(implode(',',$_['policy']['types'])); ?>" required></label>
        <label><input type="checkbox" name="require_download_password" checked disabled> Encryption passwords are mandatory for new shares</label>
        <label>New relay credential (leave blank to retain)<input name="serviceToken" type="password" autocomplete="new-password"></label>
        <label>New private scanner credential (leave blank to retain)<input name="scannerToken" type="password" autocomplete="new-password"></label>
        <p>Both scanners are mandatory. Scanning cannot be bypassed. Existing transfers are rechecked on the next background run.</p>
        <button type="submit">Save NextShuttle settings</button><p id="ns-settings-status" role="status"></p>
    </form>
</div>
