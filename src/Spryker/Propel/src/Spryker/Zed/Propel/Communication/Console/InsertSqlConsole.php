<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Propel\Communication\Console;

use Spryker\Zed\PropelOrm\Communication\Generator\Command\SqlInsertCommand;

/**
 * @method \Spryker\Zed\Propel\Business\PropelFacadeInterface getFacade()
 * @method \Spryker\Zed\Propel\Communication\PropelCommunicationFactory getFactory()
 */
class InsertSqlConsole extends AbstractPropelCommandWrapper
{
    public const COMMAND_NAME = 'propel:sql:insert';

    /**
     * @return void
     */
    protected function configure()
    {
        $this->setName(self::COMMAND_NAME);
        $this->setDescription('Insert generated SQL into database');

        parent::configure();
    }

    /**
     * @return string
     */
    public function getCommandClassName(): string
    {
        return SqlInsertCommand::class;
    }
}
