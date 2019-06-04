<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Propel\Communication\Command\Builder;

use Symfony\Component\Console\Command\Command;

interface PropelCommandBuilderInterface
{
    /**
     * @param \Symfony\Component\Console\Command\Command $propelCommand
     *
     * @return \Symfony\Component\Console\Command\Command
     */
    public function buildCommand(Command $propelCommand): Command;
}
