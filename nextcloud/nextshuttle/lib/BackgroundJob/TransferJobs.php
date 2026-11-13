<?php
declare(strict_types=1);
namespace OCA\NextShuttle\BackgroundJob;
use OCA\NextShuttle\Service\Shuttle;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
class TransferJobs extends TimedJob {
    public function __construct(ITimeFactory $time,private Shuttle $shuttle) { parent::__construct($time); $this->setInterval(60); $this->setAllowParallelRuns(false); }
    protected function run($argument): void { $this->shuttle->synchronize(); }
}
