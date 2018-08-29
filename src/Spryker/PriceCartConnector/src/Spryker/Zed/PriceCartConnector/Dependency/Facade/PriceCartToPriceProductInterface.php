<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceCartConnector\Dependency\Facade;

use Generated\Shared\Transfer\PriceProductFilterTransfer;

interface PriceCartToPriceProductInterface
{
    /**
     * @param string $sku
     * @param string|null $priceType
     *
     * @return bool
     */
    public function hasValidPrice($sku, $priceType = null);

    /**
     * @param string $sku
     * @param string|null $priceType
     *
     * @return int|null
     */
    public function findPriceBySku($sku, $priceType = null);

    /**
     * @return string
     */
    public function getDefaultPriceTypeName();

    /**
     * @param \Generated\Shared\Transfer\PriceProductFilterTransfer $priceFilterTransfer
     *
     * @return int|null
     */
    public function findPriceFor(PriceProductFilterTransfer $priceFilterTransfer);

    /**
     * @param \Generated\Shared\Transfer\PriceProductFilterTransfer $priceFilterTransfer
     *
     * @return bool
     */
    public function hasValidPriceFor(PriceProductFilterTransfer $priceFilterTransfer);
}
