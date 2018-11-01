<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductMeasurementUnit\Persistence;

use Generated\Shared\Transfer\ProductMeasurementUnitTransfer;
use Spryker\Zed\Kernel\Persistence\AbstractEntityManager;

/**
 * @method \Spryker\Zed\ProductMeasurementUnit\Persistence\ProductMeasurementUnitPersistenceFactory getFactory()
 */
class ProductMeasurementUnitEntityManager extends AbstractEntityManager implements ProductMeasurementUnitEntityManagerInterface
{
    /**
     * @param \Generated\Shared\Transfer\ProductMeasurementUnitTransfer $productMeasurementUnitTransfer
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer
     */
    public function saveProductMeasurementUnit(
        ProductMeasurementUnitTransfer $productMeasurementUnitTransfer
    ): ProductMeasurementUnitTransfer {
        $productMeasurementUnitEntity = $this->getFactory()
            ->createProductMeasurementUnitQuery()
            ->filterByCode($productMeasurementUnitTransfer->getCode())
            ->findOneOrCreate();

        $productMeasurementUnitEntity->fromArray($productMeasurementUnitTransfer->modifiedToArray());
        $productMeasurementUnitEntity->save();
        $productMeasurementUnitTransfer->fromArray($productMeasurementUnitEntity->toArray(), true);

        return $productMeasurementUnitTransfer;
    }
}
