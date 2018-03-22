<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductRelationCollector\Dependency\Facade;

class ProductRelationCollectorToPriceProductBridgeProductFacade implements ProductRelationCollectorToPriceProductFacadeInterface
{
    /**
     * @var \Spryker\Zed\PriceProduct\Business\PriceProductFacadeInterface
     */
    protected $priceProductFacade;

    /**
     * @param \Spryker\Zed\PriceProduct\Business\PriceProductFacadeInterface $priceFacade
     */
    public function __construct($priceFacade)
    {
        $this->priceProductFacade = $priceFacade;
    }

    /**
     * @param string $sku
     * @param string|null $priceTypeName
     *
     * @return int|null
     */
    public function findPriceBySku($sku, $priceTypeName = null)
    {
        return $this->priceProductFacade->findPriceBySku($sku, $priceTypeName);
    }

    /**
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findPricesBySkuForCurrentStore($sku)
    {
        return $this->priceProductFacade->findPricesBySkuForCurrentStore($sku);
    }

    /**
     * @param string $sku
     *
     * @return mixed
     */
    public function findPricesBySkuGroupedForCurrentStore($sku)
    {
        return $this->priceProductFacade->findPricesBySkuGroupedForCurrentStore($sku);
    }
}
