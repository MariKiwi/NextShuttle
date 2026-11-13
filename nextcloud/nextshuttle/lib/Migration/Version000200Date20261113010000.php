<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Migration;
use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
class Version000200Date20261113010000 extends SimpleMigrationStep {
    public function changeSchema(IOutput $output,Closure $schemaClosure,array $options): ?ISchemaWrapper {
        $schema=$schemaClosure();
        if (!$schema->hasTable('ns_transfers')) {
            $t=$schema->createTable('ns_transfers');
            foreach (['id'=>32,'owner_uid'=>64,'kind'=>16,'state'=>32,'relay_id'=>32,'label'=>240] as $name=>$length) { $t->addColumn($name,'string',['length'=>$length,'notnull'=>true]); }
            foreach (['node_id','created','expires','attempts','retry_after'] as $name) { $t->addColumn($name,'bigint',['notnull'=>true,'default'=>0]); }
            $t->addColumn('secret','text',['notnull'=>true]); $t->addColumn('options','text',['notnull'=>true]);
            $t->setPrimaryKey(['id']); $t->addIndex(['owner_uid','created'],'ns_transfer_owner');
        }
        if (!$schema->hasTable('ns_imports')) {
            $t=$schema->createTable('ns_imports');
            foreach (['id'=>32,'inbox_id'=>32,'name'=>240,'sha256'=>64,'state'=>32] as $name=>$length) { $t->addColumn($name,'string',['length'=>$length,'notnull'=>true]); }
            $t->addColumn('node_id','bigint',['notnull'=>true,'default'=>0]); $t->setPrimaryKey(['id']);
        }
        return $schema;
    }
}
