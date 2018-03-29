<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductQuantity\Business;

use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\CartPreCheckResponseTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductQuantity\Business\ProductQuantityBusinessFactory getFactory()
 */
class ProductQuantityFacade extends AbstractFacade implements ProductQuantityFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function validateItemAddProductQuantityRestrictions(CartChangeTransfer $cartChangeTransfer): CartPreCheckResponseTransfer
    {
        return $this->getFactory()
            ->createProductQuantityRestrictionValidator()
            ->validateItemAdd($cartChangeTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $productIds
     *
     * @return \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer[]
     */
    public function findProductQuantityEntitiesByProductIds(array $productIds): array
    {
        return $this->getFactory()
            ->createProductQuantityReader()
            ->findProductQuantityEntitiesByProductIds($productIds);
    }
}
