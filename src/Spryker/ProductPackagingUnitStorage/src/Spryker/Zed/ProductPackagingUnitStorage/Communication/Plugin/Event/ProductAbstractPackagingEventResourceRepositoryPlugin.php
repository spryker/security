<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event;

use Orm\Zed\Product\Persistence\Map\SpyProductAbstractTableMap;
use Spryker\Shared\ProductPackagingUnitStorage\ProductPackagingUnitStorageConfig;
use Spryker\Zed\EventBehavior\Dependency\Plugin\EventResourceRepositoryPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductPackagingUnit\Dependency\ProductPackagingUnitEvents;

/**
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Persistence\ProductPackagingUnitStorageRepositoryInterface getRepository()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Business\ProductPackagingUnitStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Communication\ProductPackagingUnitStorageCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\ProductPackagingUnitStorageConfig getConfig()
 */
class ProductAbstractPackagingEventResourceRepositoryPlugin extends AbstractPlugin implements EventResourceRepositoryPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getResourceName(): string
    {
        return ProductPackagingUnitStorageConfig::PRODUCT_ABSTRACT_PACKAGING_RESOURCE_NAME;
    }

    /**
     * {@inheritdoc}
     * - Retrieves ProductAbstractPackagingStorageTransfer collection, associated with provided product abstract IDs.
     *
     * @api
     *
     * @param int[] $productAbstractIds
     *
     * @return \Generated\Shared\Transfer\ProductAbstractPackagingStorageTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function getData(array $productAbstractIds = []): array
    {
        if (!$productAbstractIds) {
            $productAbstractIds = $this->getRepository()->findProductAbstractIdsWithProductPackagingUnit();
        }

        return $this->getFacade()->getProductAbstractPackagingStorageTransfersByProductAbstractIds($productAbstractIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getEventName(): string
    {
        return ProductPackagingUnitEvents::PRODUCT_ABSTRACT_PACKAGING_PUBLISH;
    }

    /**
     * {@inheritdoc}
     * - Returns the name of ID column needed in the ProductPackagingUnit.product_abstract_packaging.publish event.
     * - The ID is selected from the key range of ProductAbstractPackagingStorageTransfer.
     *
     * @api
     *
     * @return string|null
     */
    public function getIdColumnName(): ?string
    {
        return SpyProductAbstractTableMap::COL_ID_PRODUCT_ABSTRACT;
    }
}
