<?php
declare(strict_types=1);
namespace OCA\NextShuttle\Command;

use OCP\IConfig;
use OCP\Security\ICrypto;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\Question;

class Configure extends Command {
    public function __construct(private IConfig $config, private ICrypto $crypto) { parent::__construct(); }
    protected function configure(): void {
        $this->setName('nextshuttle:configure')->setDescription('Configure the private relay event bridge');
    }
    protected function execute(InputInterface $input, OutputInterface $output): int {
        $question = new Question('Relay service token (hidden): ');
        $question->setHidden(true)->setHiddenFallback(false);
        $token = $this->getHelper('question')->ask($input, $output, $question);
        if (!is_string($token) || !preg_match('/^[A-Za-z0-9_-]{43,256}$/D', $token)) {
            $output->writeln('Expected a random URL-safe relay token of at least 43 characters.');
            return Command::FAILURE;
        }
        $this->config->setAppValue('nextshuttle', 'relay_url', 'https://shuttle.helios.lan/');
        $this->config->setAppValue('nextshuttle', 'service_token', $this->crypto->encrypt($token));
        $output->writeln('Private event bridge configured. Certificate validation remains enabled.');
        return Command::SUCCESS;
    }
}
