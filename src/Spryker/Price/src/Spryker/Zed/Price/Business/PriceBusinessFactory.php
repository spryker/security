<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Price\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;

/**
 * @method \Spryker\Zed\Price\PriceConfig getConfig()
 */
class PriceBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\Price\PriceConfig|\Spryker\Zed\Kernel\AbstractBundleConfig
     */
    public function getModuleConfig()
    {
        return parent::getConfig();
    }
}
