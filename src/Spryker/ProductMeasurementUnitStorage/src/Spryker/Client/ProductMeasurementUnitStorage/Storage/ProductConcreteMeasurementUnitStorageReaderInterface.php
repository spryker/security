<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductMeasurementUnitStorage\Storage;

interface ProductConcreteMeasurementUnitStorageReaderInterface
{
    /**
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\SpyProductConcreteMeasurementUnitStorageEntityTransfer|null
     */
    public function findProductConcreteMeasurementUnitStorageEntity($idProduct);
}
