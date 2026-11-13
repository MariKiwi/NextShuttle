<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Service;

use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IUserManager;

class Events {
    public function __construct(private IDBConnection $db, private IGroupManager $groups, private IUserManager $users) {}
    private function owner(?string $id): ?string {
        if ($id === null) { return null; }
        $q = $this->db->getQueryBuilder();
        $q->select('owner_uid')->from('ns_owners')->where($q->expr()->eq('object_id', $q->createNamedParameter($id)));
        $result = $q->executeQuery(); $uid = $result->fetchOne(); $result->closeCursor();
        return $uid === false ? null : (string)$uid;
    }
    public function mapOwner(string $id, string $uid): void {
        $user = $this->users->get($uid);
        if (!preg_match('/^[a-f0-9]{32}$/D', $id) || $user === null || !$user->isEnabled()) {
            throw new \InvalidArgumentException('Expected a relay object ID and enabled Nextcloud user');
        }
        $existing = $this->owner($id);
        if ($existing !== null) {
            if ($existing !== $uid) { throw new \RuntimeException('Object already belongs to another user'); }
            return;
        }
        $q = $this->db->getQueryBuilder();
        $q->insert('ns_owners')->values(['object_id' => $q->createNamedParameter($id), 'owner_uid' => $q->createNamedParameter($uid)])->executeStatement();
    }
    public function ingest(array $event): void {
        EventCatalog::validate($event);
        $this->db->beginTransaction();
        try {
            $q = $this->db->getQueryBuilder();
            $q->select('sequence')->from('ns_events')->where($q->expr()->eq('sequence', $q->createNamedParameter($event['sequence'])));
            $r = $q->executeQuery(); $existing = $r->fetchOne(); $r->closeCursor();
            if ($existing !== false) { $this->db->commit(); return; }
            $owner = $this->owner($event['object_id'] ?? null) ?? $this->owner($event['parent_id'] ?? null);
            $group = $this->groups->get('admin');
            if ($group === null) { throw new \RuntimeException('Admin group unavailable'); }
            $recipients = [];
            foreach ($group->getUsers() as $user) {
                if ($user->isEnabled()) { $recipients[$user->getUID()] = true; }
            }
            if ($owner !== null) {
                $user = $this->users->get($owner);
                if ($user !== null && $user->isEnabled()) { $recipients[$owner] = true; }
            }
            $q = $this->db->getQueryBuilder();
            $q->insert('ns_events');
            foreach (['sequence', 'occurred', 'kind', 'severity', 'object_id', 'parent_id'] as $key) {
                $q->setValue($key, $q->createNamedParameter($event[$key] ?? null));
            }
            $q->setValue('owner_uid', $q->createNamedParameter($owner))->executeStatement();
            foreach (array_keys($recipients) as $uid) {
                $q = $this->db->getQueryBuilder();
                $q->insert('ns_deliveries')->values(['sequence' => $q->createNamedParameter($event['sequence']),
                    'recipient' => $q->createNamedParameter($uid), 'delivered' => $q->createNamedParameter(0)])->executeStatement();
            }
            $this->db->commit();
        } catch (\Throwable $e) { $this->db->rollBack(); throw $e; }
    }
    public function pending(): array {
        $q = $this->db->getQueryBuilder();
        $q->select('e.sequence', 'e.occurred', 'e.kind', 'e.severity', 'e.owner_uid', 'd.recipient')->from('ns_events', 'e')
            ->innerJoin('e', 'ns_deliveries', 'd', $q->expr()->eq('e.sequence', 'd.sequence'))
            ->where($q->expr()->eq('d.delivered', $q->createNamedParameter(0)))->orderBy('e.sequence', 'ASC')->setMaxResults(1000);
        $r = $q->executeQuery(); $rows = $r->fetchAll(); $r->closeCursor(); return $rows;
    }
    public function delivered(int $sequence, string $uid, int $status = 1): void {
        $q = $this->db->getQueryBuilder();
        $q->update('ns_deliveries')->set('delivered', $q->createNamedParameter($status))
            ->where($q->expr()->eq('sequence', $q->createNamedParameter($sequence)))
            ->andWhere($q->expr()->eq('recipient', $q->createNamedParameter($uid)))->executeStatement();
    }
    public function visible(string $uid): array {
        $q = $this->db->getQueryBuilder(); $q->select('*')->from('ns_events');
        if (!$this->groups->isAdmin($uid)) {
            $q->where($q->expr()->eq('owner_uid', $q->createNamedParameter($uid)));
        }
        $q->orderBy('sequence', 'DESC')->setMaxResults(100);
        $r = $q->executeQuery(); $rows = $r->fetchAll(); $r->closeCursor(); return $rows;
    }
}
