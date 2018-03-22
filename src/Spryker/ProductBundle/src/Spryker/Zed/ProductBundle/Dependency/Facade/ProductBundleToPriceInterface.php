<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Dependency\Facade;

interface ProductBundleToPriceInterface
{
    /**
     * @return string
     */
    public function getNetPriceModeIdentifier();

    /**
     * @return string
     */
    public function getGrossPriceModeIdentifier();
}
