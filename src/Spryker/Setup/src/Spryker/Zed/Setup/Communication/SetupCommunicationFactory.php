<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Setup\Communication;

use Spryker\Zed\Kernel\Communication\AbstractCommunicationFactory;

/**
 * @method \Spryker\Zed\Setup\SetupConfig getConfig()
 */
class SetupCommunicationFactory extends AbstractCommunicationFactory
{
    /**
     * @return array
     */
    public function getSetupInstallCommandNames()
    {
        return $this->getConfig()->getSetupInstallCommandNames();
    }
}
