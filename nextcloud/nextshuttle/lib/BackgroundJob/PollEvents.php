<?php
declare(strict_types=1);
namespace OCA\NextShuttle\BackgroundJob;

use OCA\NextShuttle\Service\Events;
use OCA\NextShuttle\Service\Relay;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IUserManager;
use OCP\Notification\IManager;
use Psr\Log\LoggerInterface;

class PollEvents extends TimedJob {
    public function __construct(ITimeFactory $time, private Relay $relay, private Events $events,
        private IConfig $config, private IManager $notifications, private IUserManager $users,
        private LoggerInterface $logger, private IGroupManager $groups) {
        parent::__construct($time);
        $this->setInterval(60);
        $this->setAllowParallelRuns(false);
    }
    protected function run($argument): void {
        if ($this->config->getAppValue('nextshuttle', 'service_token') === '') { return; }
        try {
            $cursor = (int)$this->config->getAppValue('nextshuttle', 'event_cursor', '0');
            for ($batch = 0; $batch < 5; $batch++) {
                $data = $this->relay->call('events/read', ['after' => $cursor, 'limit' => 100]);
                $journal = $data['journal_id'] ?? '';
                $expectedJournal = $this->config->getAppValue('nextshuttle', 'journal_id', '');
                if (!is_string($journal) || !preg_match('/^[a-f0-9]{32}$/D', $journal)
                    || ($expectedJournal !== '' && $journal !== $expectedJournal)) {
                    throw new \UnexpectedValueException('Relay journal changed; reconciliation required');
                }
                if ($expectedJournal === '') { $this->config->setAppValue('nextshuttle', 'journal_id', $journal); }
                if (!is_array($data['events'] ?? null) || count($data['events']) > 100) {
                    throw new \UnexpectedValueException('Invalid event batch');
                }
                foreach ($data['events'] as $event) {
                    if (!is_array($event) || ($event['sequence'] ?? 0) !== $cursor + 1) {
                        throw new \UnexpectedValueException('Event journal gap or reset');
                    }
                    $this->events->ingest($event);
                    $cursor = $event['sequence'];
                    $this->config->setAppValue('nextshuttle', 'event_cursor', (string)$cursor);
                }
                if (count($data['events']) < 100) { break; }
            }
            $this->relay->call('events/ack', ['through' => $cursor]);
            $this->config->setAppValue('nextshuttle', 'last_event_sync', (string)time());
        } catch (\Throwable $e) {
            // No exception/request dump: those can contain authentication material.
            $this->logger->error('NextShuttle event collection failed; journal retained', ['app' => 'nextshuttle']);
        }
        // Already-ingested deliveries continue even when the relay is unavailable.
        foreach ($this->events->pending() as $event) {
            $uid = (string)$event['recipient'];
            $user = $this->users->get($uid);
            if ($user === null || !$user->isEnabled()
                || (!$this->groups->isAdmin($uid) && $uid !== ($event['owner_uid'] ?? null))) {
                $this->events->delivered((int)$event['sequence'], $uid, 2);
                continue;
            }
            try {
                $notification = $this->notifications->createNotification();
                $notification->setApp('nextshuttle')->setUser($uid)
                    ->setDateTime((new \DateTime())->setTimestamp((int)$event['occurred']))
                    ->setObject('event', (string)$event['sequence'])
                    ->setSubject('security_event', ['kind' => $event['kind'], 'severity' => $event['severity']]);
                $this->notifications->notify($notification);
                $this->events->delivered((int)$event['sequence'], $uid);
            } catch (\Throwable $e) {
                $this->logger->error('NextShuttle notification delivery pending retry', ['app' => 'nextshuttle']);
            }
        }
    }
}
