<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\ProductQuantity;

use Generated\Shared\Transfer\ProductQuantityTransfer;
use Spryker\Service\Kernel\AbstractService;

/**
 * @method \Spryker\Service\ProductQuantity\ProductQuantityServiceFactory getFactory()
 */
class ProductQuantityService extends AbstractService implements ProductQuantityServiceInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductQuantityTransfer $productQuantityTransfer
     * @param float $quantity
     *
     * @return float
     */
    public function getNearestQuantity(ProductQuantityTransfer $productQuantityTransfer, float $quantity): float
    {
        return $this->getFactory()
            ->createProductQuantityRounder()
            ->getNearestQuantity($productQuantityTransfer, $quantity);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return float
     */
    public function getDefaultMinimumQuantity(): float
    {
        return $this->getFactory()
            ->createConfigReader()
            ->getDefaultMinimumQuantity();
    }
}
