<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Migration;
use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
class Version000300Date20261116000000 extends SimpleMigrationStep {
    public function changeSchema(IOutput $output,Closure $schemaClosure,array $options): ?ISchemaWrapper {
        $schema=$schemaClosure();$table=$schema->getTable('ns_events');
        foreach (['client_ip'=>45,'country'=>2,'ip_source'=>20,'country_status'=>32] as $name=>$length) {
            if (!$table->hasColumn($name)) { $table->addColumn($name,'string',['length'=>$length,'notnull'=>false]); }
        }
        return $schema;
    }
}
