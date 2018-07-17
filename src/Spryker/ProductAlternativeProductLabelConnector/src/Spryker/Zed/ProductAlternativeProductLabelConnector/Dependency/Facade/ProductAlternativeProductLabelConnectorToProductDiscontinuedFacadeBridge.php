<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAlternativeProductLabelConnector\Dependency\Facade;

class ProductAlternativeProductLabelConnectorToProductDiscontinuedFacadeBridge implements ProductAlternativeProductLabelConnectorToProductDiscontinuedFacadeInterface
{
    /**
     * @var \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedFacadeInterface
     */
    protected $productDiscontinuedFacade;

    /**
     * @param \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedFacadeInterface $productDiscontinuedFacade
     */
    public function __construct($productDiscontinuedFacade)
    {
        $this->productDiscontinuedFacade = $productDiscontinuedFacade;
    }

    /**
     * @param int[] $productIds
     *
     * @return bool
     */
    public function areAllConcreteProductsDiscontinued(array $productIds): bool
    {
        return $this->productDiscontinuedFacade->areAllConcreteProductsDiscontinued($productIds);
    }

    /**
     * @param int $idProduct
     *
     * @return bool
     */
    public function isConcreteDiscontinued(int $idProduct): bool
    {
        return $this->productDiscontinuedFacade->isConcreteDiscontinued($idProduct);
    }
}
