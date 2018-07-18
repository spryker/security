<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductMeasurementUnitStorage\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductMeasurementUnitStorage\Business\ProductMeasurementUnitStorageBusinessFactory getFactory()
 */
class ProductMeasurementUnitStorageFacade extends AbstractFacade implements ProductMeasurementUnitStorageFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $productMeasurementUnitIds
     *
     * @return void
     */
    public function publishProductMeasurementUnit(array $productMeasurementUnitIds): void
    {
        $this->getFactory()->createProductMeasurementUnitStorageWriter()->publish($productMeasurementUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $productIds
     *
     * @return void
     */
    public function publishProductConcreteMeasurementUnit(array $productIds): void
    {
        $this->getFactory()->createProductConcreteMeasurementUnitStorageWriter()->publish($productIds);
    }

    /**
     * @api
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function findAllProductMeasurementUnitTransfers(): array
    {
        return $this->getFactory()->getProductMeasurementUnitFacade()->findAllProductMeasurementUnitTransfers();
    }

    /**
     * @api
     *
     * @param int[] $productMeasurementUnitIds
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function findProductMeasurementUnitTransfers(array $productMeasurementUnitIds): array
    {
        return $this->getFactory()->getProductMeasurementUnitFacade()->findProductMeasurementUnitTransfers($productMeasurementUnitIds);
    }

    /**
     * @api
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function getSalesUnits(): array
    {
        return $this->getFactory()->getProductMeasurementUnitFacade()->getSalesUnits();
    }

    /**
     * @api
     *
     * @param int[] $salesUnitsIds
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function getSalesUnitsByIds(array $salesUnitsIds): array
    {
        return $this->getFactory()->getProductMeasurementUnitFacade()->getSalesUnitsByIds($salesUnitsIds);
    }
}
