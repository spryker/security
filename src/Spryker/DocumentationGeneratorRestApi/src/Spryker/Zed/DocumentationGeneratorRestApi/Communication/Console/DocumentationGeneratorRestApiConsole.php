<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DocumentationGeneratorRestApi\Communication\Console;

use Spryker\Shared\Config\Environment;
use Spryker\Zed\Kernel\Communication\Console\Console;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * @method \Spryker\Zed\DocumentationGeneratorRestApi\Business\DocumentationGeneratorRestApiFacadeInterface getFacade()
 */
class DocumentationGeneratorRestApiConsole extends Console
{
    protected const COMMAND_NAME = 'rest-api:generate:documentation';
    protected const DESCRIPTION = 'Generates documentation for enabled Rest API endpoints.';

    protected const APPLICATION_ENV_DEVELOPMENT = 'development';
    protected const EXCEPTION_NOT_ALLOWED_MESSAGE = 'This action is allowed only for development environment.';

    /**
     * @return void
     */
    protected function configure(): void
    {
        parent::configure();

        $this->setName(static::COMMAND_NAME)
            ->setDescription(static::DESCRIPTION);
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int|null
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        if (Environment::isNotDevelopment()) {
            $this->error(static::EXCEPTION_NOT_ALLOWED_MESSAGE);

            return static::CODE_ERROR;
        }

        $this->getFacade()->generateDocumentation();

        return static::CODE_SUCCESS;
    }
}
