<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade;

use Generated\Shared\Transfer\ProductPackagingLeadProductTransfer;

class ProductPackagingUnitStorageToProductPackagingUnitFacadeBridge implements ProductPackagingUnitStorageToProductPackagingUnitFacadeInterface
{
    /**
     * @var \Spryker\Zed\ProductPackagingUnit\Business\ProductPackagingUnitFacadeInterface
     */
    protected $productPackagingUnitFacade;

    /**
     * @param \Spryker\Zed\ProductPackagingUnit\Business\ProductPackagingUnitFacadeInterface $productPackagingUnitFacade
     */
    public function __construct($productPackagingUnitFacade)
    {
        $this->productPackagingUnitFacade = $productPackagingUnitFacade;
    }

    /**
     * @param int $productAbstractId
     *
     * @return \Generated\Shared\Transfer\ProductPackagingLeadProductTransfer|null
     */
    public function getProductPackagingLeadProductByAbstractId(
        int $productAbstractId
    ): ?ProductPackagingLeadProductTransfer {
        return $this->productPackagingUnitFacade->getProductPackagingLeadProductByAbstractId($productAbstractId);
    }

    /**
     * @return string
     */
    public function getDefaultPackagingUnitTypeName(): string
    {
        return $this->productPackagingUnitFacade->getDefaultPackagingUnitTypeName();
    }
}
