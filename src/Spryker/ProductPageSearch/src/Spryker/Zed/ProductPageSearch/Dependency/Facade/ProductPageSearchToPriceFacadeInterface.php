<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPageSearch\Dependency\Facade;

interface ProductPageSearchToPriceFacadeInterface
{
    /**
     * @return string
     */
    public function getDefaultPriceMode();

    /**
     * @return string
     */
    public function getGrossPriceModeIdentifier();
}
