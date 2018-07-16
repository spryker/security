<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductMeasurementUnitStorage\Persistence\Propel\Mapper;

use Generated\Shared\Transfer\SpyProductMeasurementUnitStorageEntityTransfer;
use Orm\Zed\ProductMeasurementUnitStorage\Persistence\SpyProductMeasurementUnitStorage;

class ProductMeasurementUnitStorageMapper implements ProductMeasurementUnitStorageMapperInterface
{
    /**
     * @param \Orm\Zed\ProductMeasurementUnitStorage\Persistence\SpyProductMeasurementUnitStorage $spyProductMeasurementUnitStorageEntity
     * @param \Generated\Shared\Transfer\SpyProductMeasurementUnitStorageEntityTransfer $productMeasurementUnitStorageEntityTransfer
     *
     * @return \Orm\Zed\ProductMeasurementUnitStorage\Persistence\SpyProductMeasurementUnitStorage
     */
    public function hydrateSpyProductMeasurementUnitStorageEntity(
        SpyProductMeasurementUnitStorage $spyProductMeasurementUnitStorageEntity,
        SpyProductMeasurementUnitStorageEntityTransfer $productMeasurementUnitStorageEntityTransfer
    ): SpyProductMeasurementUnitStorage {
        $spyProductMeasurementUnitStorageEntity->fromArray($productMeasurementUnitStorageEntityTransfer->toArray());

        return $spyProductMeasurementUnitStorageEntity;
    }
}
