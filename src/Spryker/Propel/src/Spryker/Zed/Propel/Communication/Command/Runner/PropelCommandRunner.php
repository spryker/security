<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Propel\Communication\Command\Runner;

use Spryker\Zed\Propel\Communication\Command\Input\PropelCommandInputBuilderInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputDefinition;
use Symfony\Component\Console\Output\OutputInterface;

class PropelCommandRunner implements PropelCommandRunnerInterface
{
    /**
     * @var \Spryker\Zed\Propel\Communication\Command\Input\PropelCommandInputBuilderInterface
     */
    protected $inputBuilder;

    /**
     * @param \Spryker\Zed\Propel\Communication\Command\Input\PropelCommandInputBuilderInterface $inputBuilder
     */
    public function __construct(PropelCommandInputBuilderInterface $inputBuilder)
    {
        $this->inputBuilder = $inputBuilder;
    }

    /**
     * @param \Symfony\Component\Console\Command\Command $command
     * @param \Symfony\Component\Console\Input\InputDefinition $inputDefinition
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    public function runCommand(
        Command $command,
        InputDefinition $inputDefinition,
        OutputInterface $output
    ): int {
        $input = $this->inputBuilder
            ->buildInput(
                $inputDefinition,
                $command->getDefinition()
            );

        return $command->run($input, $output);
    }
}
