<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;
use OCP\IDBConnection;
use OCP\Security\ICrypto;
class Transfers {
    public function __construct(private IDBConnection $db,private ICrypto $crypto) {}
    public function get(string $id,?string $uid=null): array {
        Relay::id($id); $q=$this->db->getQueryBuilder();
        $q->select('*')->from('ns_transfers')->where($q->expr()->eq('id',$q->createNamedParameter($id)));
        if ($uid!==null) { $q->andWhere($q->expr()->eq('owner_uid',$q->createNamedParameter($uid))); }
        $r=$q->executeQuery(); $row=$r->fetch(); $r->closeCursor();
        if (!$row) { throw new \OCP\Files\NotFoundException('Transfer not found'); } return $this->decode($row);
    }
    private function decode(array $row): array {
        $row['secret']=json_decode($this->crypto->decrypt($row['secret']),true,16,JSON_THROW_ON_ERROR);
        $row['options']=json_decode($row['options'],true,16,JSON_THROW_ON_ERROR);
        foreach (['node_id','created','expires','attempts','retry_after'] as $key) { $row[$key]=(int)$row[$key]; } return $row;
    }
    public function list(?string $uid=null,bool $active=false): array {
        $q=$this->db->getQueryBuilder(); $q->select('*')->from('ns_transfers');
        if ($uid!==null) { $q->where($q->expr()->eq('owner_uid',$q->createNamedParameter($uid))); }
        if ($active) { $q->andWhere($q->expr()->in('state',$q->createNamedParameter(['queued','preparing','ready','retry','revoking'],\OCP\DB\QueryBuilder\IQueryBuilder::PARAM_STR_ARRAY))); }
        $q->orderBy('created',$active?'ASC':'DESC')->setMaxResults(10000); $r=$q->executeQuery(); $rows=$r->fetchAll(); $r->closeCursor();
        return array_map($this->decode(...),$rows);
    }
    public function insert(#[\SensitiveParameter] array $row): void {
        $row['secret']=$this->crypto->encrypt(json_encode($row['secret'],JSON_THROW_ON_ERROR));
        $row['options']=json_encode($row['options'],JSON_THROW_ON_ERROR);
        $q=$this->db->getQueryBuilder(); $q->insert('ns_transfers');
        foreach ($row as $k=>$v) { $q->setValue($k,$q->createNamedParameter($v)); } $q->executeStatement();
    }
    public function update(string $id,#[\SensitiveParameter] array $values): void {
        $q=$this->db->getQueryBuilder(); $q->update('ns_transfers');
        foreach ($values as $k=>$v) {
            if (!in_array($k,['state','relay_id','secret','options','expires','attempts','retry_after'],true)) { throw new \InvalidArgumentException('Invalid transfer update'); }
            if ($k==='secret') { $v=$this->crypto->encrypt(json_encode($v,JSON_THROW_ON_ERROR)); }
            if ($k==='options') { $v=json_encode($v,JSON_THROW_ON_ERROR); }
            $q->set($k,$q->createNamedParameter($v));
        }
        $q->where($q->expr()->eq('id',$q->createNamedParameter($id)))->executeStatement();
    }
    public function receipt(string $id): ?array {
        $q=$this->db->getQueryBuilder(); $q->select('*')->from('ns_imports')->where($q->expr()->eq('id',$q->createNamedParameter(Relay::id($id))));
        $r=$q->executeQuery(); $row=$r->fetch(); $r->closeCursor(); return $row?:null;
    }
    public function plan(string $id,string $inbox,string $name,string $hash): array {
        $old=$this->receipt($id); if ($old!==null) { if ($old['sha256']!==$hash) { throw new \RuntimeException('Import content changed'); } return $old; }
        $q=$this->db->getQueryBuilder(); $q->insert('ns_imports')->values([
            'id'=>$q->createNamedParameter($id),'inbox_id'=>$q->createNamedParameter($inbox),'name'=>$q->createNamedParameter($name),
            'sha256'=>$q->createNamedParameter($hash),'state'=>$q->createNamedParameter('planned'),'node_id'=>$q->createNamedParameter(0)])->executeStatement();
        return $this->receipt($id);
    }
    public function imported(string $id,int $node,string $state='stored'): void {
        $q=$this->db->getQueryBuilder(); $q->update('ns_imports')->set('state',$q->createNamedParameter($state))->set('node_id',$q->createNamedParameter($node))
            ->where($q->expr()->eq('id',$q->createNamedParameter($id)))->executeStatement();
    }
    public static function publicRow(array $row): array {
        $out=array_intersect_key($row,array_flip(['id','label','kind','state','created','expires','attempts','node_id']));
        $out['usage']=$row['options']['usage']??[];
        if ($row['state']==='ready'&&$row['expires']>time()) {
            if ($row['kind']==='download') { $code='D.'.$row['id'].'.'.$row['secret']['token'].'.'.$row['secret']['key']; }
            else { $code='U.'.$row['id'].'.'.$row['secret']['public']; }
            $out['code']=$code; $out['url']='https://helios-public.tail43e437.ts.net/nextshuttle/#'.$code;
        }
        return $out;
    }
}
