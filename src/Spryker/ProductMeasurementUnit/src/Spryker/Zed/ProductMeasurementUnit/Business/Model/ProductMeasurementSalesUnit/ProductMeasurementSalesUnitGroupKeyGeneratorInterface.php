<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductMeasurementUnit\Business\Model\ProductMeasurementSalesUnit;

use Generated\Shared\Transfer\ItemTransfer;

interface ProductMeasurementSalesUnitGroupKeyGeneratorInterface
{
    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $item
     *
     * @return string
     */
    public function expandItemGroupKey(ItemTransfer $item): string;
}
