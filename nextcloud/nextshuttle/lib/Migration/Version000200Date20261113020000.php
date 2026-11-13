<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Migration;
use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
class Version000200Date20261113020000 extends SimpleMigrationStep {
    public function changeSchema(IOutput $output,Closure $schemaClosure,array $options): ?ISchemaWrapper {
        $schema=$schemaClosure();
        if (!$schema->hasTable('ns_reports')) {
            $t=$schema->createTable('ns_reports');
            $t->addColumn('id','string',['length'=>32,'notnull'=>true]);
            $t->addColumn('kind','string',['length'=>64,'notnull'=>true]);
            $t->addColumn('object_id','string',['length'=>32,'notnull'=>false]);
            $t->addColumn('parent_id','string',['length'=>32,'notnull'=>false]);
            $t->addColumn('created','bigint',['notnull'=>true]);$t->setPrimaryKey(['id']);
        }
        return $schema;
    }
}
