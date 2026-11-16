<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Notification;

use OCA\NextShuttle\Service\EventCatalog;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Notification\INotification;
use OCP\Notification\INotifier;
use OCP\Notification\UnknownNotificationException;

class Notifier implements INotifier {
    public function __construct(private IFactory $l10n, private IURLGenerator $urls) {}
    public function getID(): string { return 'nextshuttle'; }
    public function getName(): string { return 'NextShuttle'; }
    public function prepare(INotification $notification, string $languageCode): INotification {
        $parameters = $notification->getSubjectParameters();
        $kind = $parameters['kind'] ?? '';
        if ($notification->getApp() !== 'nextshuttle' || $notification->getSubject() !== 'security_event'
            || !isset(EventCatalog::LABELS[$kind])) { throw new UnknownNotificationException(); }
        $l = $this->l10n->get('nextshuttle', $languageCode);
        $message=$l->t('Open NextShuttle for the event record. Event %s.',[$notification->getObjectId()]);
        if (is_string($parameters['client_ip']??null)&&filter_var($parameters['client_ip'],FILTER_VALIDATE_IP)!==false) {
            $country=$parameters['country']??null;
            $name=is_string($country)&&preg_match('/^[A-Z]{2}$/D',$country)?(class_exists('Locale')?\Locale::getDisplayRegion('und_'.$country,$languageCode):$country):$l->t('Unknown');
            $message=$l->t('IP: %s · Estimated country: %s.',[$parameters['client_ip'],$name]).' '.$message;
            if (($parameters['ip_source']??null)==='peer') { $message.=' '.$l->t('Address observed directly; proxy forwarding is not verified.'); }
        }
        $notification->setParsedSubject('NextShuttle: ' . $l->t(EventCatalog::LABELS[$kind]))
            ->setParsedMessage($message)
            ->setLink($this->urls->linkToRouteAbsolute('nextshuttle.page.index'))
            ->setIcon($this->urls->getAbsoluteURL($this->urls->imagePath('nextshuttle', 'app.svg')));
        return $notification;
    }
}
