<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductTaxSetsRestApi\Communication\Console;

use Spryker\Zed\Kernel\Communication\Console\Console;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * @deprecated Use Spryker\Zed\Uuid\Communication\Console\UuidGeneratorConsole instead.
 *
 * @method \Spryker\Zed\ProductTaxSetsRestApi\Business\ProductTaxSetsRestApiFacade getFacade()
 * @method \Spryker\Zed\ProductTaxSetsRestApi\Communication\ProductTaxSetsRestApiCommunicationFactory getFactory()
 */
class ProductTaxSetsRestApiConsole extends Console
{
    protected const COMMAND_NAME = 'tax-sets:uuid:update';
    protected const DESCRIPTION = 'Generates UUIDs for existing spy_tax_set records without UUID';

    /**
     * @return void
     */
    protected function configure(): void
    {
        $this->setName(static::COMMAND_NAME)
            ->setDescription(static::DESCRIPTION)
            ->setHelp('<info>' . static::COMMAND_NAME . ' -h</info>');
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int|null
     */
    protected function execute(InputInterface $input, OutputInterface $output): void
    {
        $this->getFacade()->updateTaxSetsWithoutUuid();

        return null;
    }
}
