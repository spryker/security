<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Storage\Communication\Console;

use Spryker\Zed\Kernel\Communication\Console\Console;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * @method \Spryker\Zed\Storage\Business\StorageFacadeInterface getFacade()
 */
class StorageImportRdbConsole extends Console
{
    const COMMAND_NAME = 'storage:redis:import';
    const DESCRIPTION = 'This command will import a rdb file.';

    const ARGUMENT_SOURCE = 'source';

    /**
     * @return void
     */
    protected function configure()
    {
        $this->setName(static::COMMAND_NAME);
        $this->setDescription(static::DESCRIPTION);

        $this->addArgument(static::ARGUMENT_SOURCE, InputArgument::REQUIRED, 'Path of the rdb file.');

        parent::configure();
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $source = $input->getArgument(static::ARGUMENT_SOURCE);

        if ($this->getFacade()->import($source)) {
            $this->info(sprintf('Imported rdb file "%s"', $source));

            return static::CODE_SUCCESS;
        }

        $this->error(sprintf('Could not import rdb file.'));

        return static::CODE_ERROR;
    }
}
