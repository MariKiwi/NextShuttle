<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Command;

use OCA\NextShuttle\Service\Events;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Owner extends Command {
    public function __construct(private Events $events) { parent::__construct(); }
    protected function configure(): void {
        $this->setName('nextshuttle:owner')->setDescription('Associate a test relay object with its real Nextcloud owner')
            ->addArgument('object', InputArgument::REQUIRED)->addArgument('user', InputArgument::REQUIRED);
    }
    protected function execute(InputInterface $input, OutputInterface $output): int {
        $this->events->mapOwner((string)$input->getArgument('object'), (string)$input->getArgument('user'));
        $output->writeln('Owner mapped. Applies to subsequently collected events.');
        return Command::SUCCESS;
    }
}
