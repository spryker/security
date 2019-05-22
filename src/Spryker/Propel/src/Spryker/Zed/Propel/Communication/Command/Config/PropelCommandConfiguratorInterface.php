<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Propel\Communication\Command\Config;

use Spryker\Zed\PropelOrm\Business\Generator\ConfigurablePropelCommandInterface;

interface PropelCommandConfiguratorInterface
{
    /**
     * @param \Spryker\Zed\PropelOrm\Business\Generator\ConfigurablePropelCommandInterface $propelConfigurable
     *
     * @return \Spryker\Zed\PropelOrm\Business\Generator\ConfigurablePropelCommandInterface
     */
    public function configurePropelCommand(ConfigurablePropelCommandInterface $propelConfigurable): ConfigurablePropelCommandInterface;
}
