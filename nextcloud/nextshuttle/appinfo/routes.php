<?php
declare(strict_types=1);
return ['routes' => [
    ['name' => 'page#index', 'url' => '/', 'verb' => 'GET'],
    ['name'=>'transfer#index','url'=>'/transfers','verb'=>'GET'],
    ['name'=>'transfer#create','url'=>'/transfers','verb'=>'POST'],
    ['name'=>'transfer#revoke','url'=>'/transfers/{id}/revoke','verb'=>'POST'],
    ['name'=>'transfer#retry','url'=>'/transfers/{id}/retry','verb'=>'POST'],
    ['name'=>'transfer#password','url'=>'/transfers/{id}/password','verb'=>'POST'],
    ['name'=>'admin#save','url'=>'/settings','verb'=>'POST'],
]];
