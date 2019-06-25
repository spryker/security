<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\ProductQuantity;

use Generated\Shared\Transfer\ProductQuantityTransfer;

interface ProductQuantityServiceInterface
{
    /**
     * Specification:
     *  - Returns nearest valid quantity based on provided quantity and product quantity restrictions.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductQuantityTransfer $productQuantityTransfer
     * @param float $quantity
     *
     * @return float
     */
    public function getNearestQuantity(ProductQuantityTransfer $productQuantityTransfer, float $quantity): float;

    /**
     * Specification:
     * - gets default minimum quantity value from config.
     *
     * @api
     *
     * @return float
     */
    public function getDefaultMinimumQuantity(): float;

    /**
     * Specification:
     * - Reads default quantity interval value from config.
     *
     * @api
     *
     * @return float
     */
    public function getDefaultInterval(): float;
}
