<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Dependency\Facade;

use Generated\Shared\Transfer\PriceProductFilterTransfer;

interface ProductBundleToPriceProductFacadeInterface
{
    /**
     * @param string $sku
     * @param string|null $priceType
     *
     * @return int|null
     */
    public function findPriceBySku($sku, $priceType = null);

    /**
     * @param \Generated\Shared\Transfer\PriceProductFilterTransfer $priceProductFilterTransfer
     *
     * @return int|null
     */
    public function findPriceFor(PriceProductFilterTransfer $priceProductFilterTransfer);
}
