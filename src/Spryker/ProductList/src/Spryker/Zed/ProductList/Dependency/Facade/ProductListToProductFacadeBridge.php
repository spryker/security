<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductList\Dependency\Facade;

class ProductListToProductFacadeBridge implements ProductListToProductFacadeInterface
{
    /**
     * @var \Spryker\Zed\Product\Business\ProductFacadeInterface
     */
    protected $productFacade;

    /**
     * @param \Spryker\Zed\Product\Business\ProductFacadeInterface $productFacade
     */
    public function __construct($productFacade)
    {
        $this->productFacade = $productFacade;
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return int[]
     */
    public function getProductConcreteIdsByAbstractProductIds(array $productAbstractIds): array
    {
        return $this->productFacade->getProductConcreteIdsByAbstractProductIds($productAbstractIds);
    }
}
