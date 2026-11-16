<?php
declare(strict_types=1);
/** @var array $_ */
$stamp=static fn($value): string=>is_numeric($value)&&(int)$value>0?gmdate('Y-m-d H:i:s',(int)$value).' UTC':'Not checked yet';
?>
<div class="section ns-admin">
    <h2>NextShuttle</h2>
    <p>Control who can share, how long transfers stay open and how much they can receive.</p>
    <div class="ns-service-status">
        <p><strong>Private relay</strong> · <?php p($_['configured']?'Credential configured':'Setup required'); ?> · <a href="https://shuttle.helios.lan/" target="_blank" rel="noopener noreferrer">Open administration</a></p>
        <p><strong>Malware scanning</strong> · <?php p($_['scanner_health']); ?> · Checked <?php p($stamp($_['scanner_health_checked'])); ?></p>
        <p><strong>Event collection</strong> · <?php p($stamp($_['last_sync'])); ?> · Through event <?php p($_['cursor']); ?></p>
        <?php if ($_['needs_reconcile']): ?><p>Existing shares are waiting for the background job to apply the updated policies.</p><?php endif; ?>
    </div>
    <form id="ns-policy">
        <fieldset class="ns-fieldset"><legend>Sharing limits</legend><div class="ns-policy-grid">
        <?php foreach ([
            'max_ttl'=>['Maximum sharing time (hours)',3600],
            'default_ttl'=>['Default sharing time (hours)',3600],
            'max_file'=>['Maximum file size (MiB, up to 32)',1048576],
            'max_active'=>['Active transfers per user',1],
            'max_user_bytes'=>['Reserved capacity per user (MiB)',1048576],
            'max_downloads'=>['Maximum downloads per share',1],
            'max_inbox_files'=>['Maximum files per inbox',1],
            'max_inbox_bytes'=>['Total inbox capacity (MiB)',1048576],
            'min_password'=>['Minimum password characters (16–128)',1]
        ] as $key=>[$label,$factor]):
            $minimum=in_array($key,['max_ttl','default_ttl'],true)?60:($key==='min_password'?16:1);
            $maximum=match($key){'max_ttl','default_ttl'=>604800,'max_file'=>33554432,'max_user_bytes'=>10737418240,'max_inbox_bytes'=>1073741824,'min_password'=>128,default=>1000};
        ?>
            <label><?php p($label); ?><input type="number" name="<?php p($key); ?>" data-factor="<?php p($factor); ?>" value="<?php p($_['policy'][$key]/$factor); ?>" min="<?php p($minimum/$factor); ?>" max="<?php p($maximum/$factor); ?>" step="<?php p($factor===1?'1':'any'); ?>" required></label>
        <?php endforeach; ?>
        </div></fieldset>
        <fieldset class="ns-fieldset"><legend>Access and content</legend>
            <label>Eligible group IDs (comma separated; empty allows all eligible users)<input name="groups" value="<?php p(implode(',',$_['policy']['groups'])); ?>"></label>
            <label>Allowed file extensions (comma separated)<input name="types" value="<?php p(implode(',',$_['policy']['types'])); ?>" required></label>
            <label class="ns-check"><input type="checkbox" name="require_download_password" checked disabled> Encryption passwords are mandatory for new shares</label>
            <p class="ns-hint">Nextcloud's sharing permissions also apply. Both malware scanners are mandatory and cannot be bypassed.</p>
        </fieldset>
        <details class="ns-fieldset"><summary>Connection credentials</summary>
            <p class="ns-hint">These belong to the private relay and scanner services, not the relay administrator login. Leave them blank to keep the current values.</p>
            <label>New relay credential<input name="serviceToken" type="password" autocomplete="new-password"></label>
            <label>New private scanner credential<input name="scannerToken" type="password" autocomplete="new-password"></label>
        </details>
        <div class="ns-settings-actions"><button type="submit" class="primary">Save NextShuttle settings</button><p id="ns-settings-status" role="status"></p></div>
    </form>
</div>
