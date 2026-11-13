<?php
declare(strict_types=1);
/** @var array $_ */
?>
<div class="section">
    <h2>NextShuttle — development build</h2>
    <p>Private relay: https://shuttle.helios.lan/</p>
    <p>Event bridge configured: <?php p($_['configured'] ? 'Yes' : 'No'); ?></p>
    <p>Last successful collection (Unix timestamp): <?php p($_['last_sync']); ?></p>
    <p>Collected through event: <?php p($_['cursor']); ?></p>
    <p>Configure the protected credential with the nextshuttle:configure occ command.</p>
    <p>File sharing, upload scanning and policy editing are not yet ready for deployment.</p>
</div>
