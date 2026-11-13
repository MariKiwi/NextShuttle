<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version000100Date20261113000000 extends SimpleMigrationStep {
    public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
        $schema = $schemaClosure();
        if (!$schema->hasTable('ns_events')) {
            $table = $schema->createTable('ns_events');
            $table->addColumn('sequence', 'bigint', ['notnull' => true]);
            $table->addColumn('occurred', 'bigint', ['notnull' => true]);
            $table->addColumn('kind', 'string', ['length' => 64, 'notnull' => true]);
            $table->addColumn('severity', 'string', ['length' => 16, 'notnull' => true]);
            $table->addColumn('object_id', 'string', ['length' => 32, 'notnull' => false]);
            $table->addColumn('parent_id', 'string', ['length' => 32, 'notnull' => false]);
            $table->addColumn('owner_uid', 'string', ['length' => 64, 'notnull' => false]);
            $table->setPrimaryKey(['sequence']);
            $table->addIndex(['owner_uid', 'sequence'], 'ns_event_owner');
        }
        if (!$schema->hasTable('ns_owners')) {
            $table = $schema->createTable('ns_owners');
            $table->addColumn('object_id', 'string', ['length' => 32, 'notnull' => true]);
            $table->addColumn('owner_uid', 'string', ['length' => 64, 'notnull' => true]);
            $table->setPrimaryKey(['object_id']);
        }
        if (!$schema->hasTable('ns_deliveries')) {
            $table = $schema->createTable('ns_deliveries');
            $table->addColumn('sequence', 'bigint', ['notnull' => true]);
            $table->addColumn('recipient', 'string', ['length' => 64, 'notnull' => true]);
            $table->addColumn('delivered', 'smallint', ['notnull' => true, 'default' => 0]);
            $table->setPrimaryKey(['sequence', 'recipient']);
            $table->addIndex(['delivered', 'sequence'], 'ns_delivery_pending');
        }
        return $schema;
    }
}
