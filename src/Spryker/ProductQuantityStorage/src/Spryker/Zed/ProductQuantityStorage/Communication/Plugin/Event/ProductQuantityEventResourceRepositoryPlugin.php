<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductQuantityStorage\Communication\Plugin\Event;

use Orm\Zed\ProductQuantity\Persistence\Map\SpyProductQuantityTableMap;
use Spryker\Shared\ProductQuantityStorage\ProductQuantityStorageConfig;
use Spryker\Zed\EventBehavior\Dependency\Plugin\EventResourceRepositoryPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductQuantity\Dependency\ProductQuantityEvents;

/**
 * @method \Spryker\Zed\ProductQuantityStorage\Persistence\ProductQuantityStorageRepositoryInterface getRepository()
 * @method \Spryker\Zed\ProductQuantityStorage\Business\ProductQuantityStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductQuantityStorage\Communication\ProductQuantityStorageCommunicationFactory getFactory()
 */
class ProductQuantityEventResourceRepositoryPlugin extends AbstractPlugin implements EventResourceRepositoryPluginInterface
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
        return ProductQuantityStorageConfig::PRODUCT_QUANTITY_RESOURCE_NAME;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $ids
     *
     * @return \Generated\Shared\Transfer\ProductQuantityTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function getData(array $ids = []): array
    {
        if (!empty($ids)) {
            $this->getFacade()->findProductQuantityByProductIdsTransfers($ids);
        }
        return $this->getFacade()->findProductQuantityTransfers();
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
        return ProductQuantityEvents::PRODUCT_QUANTITY_PUBLISH;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string|null
     */
    public function getIdColumnName(): ?string
    {
        return SpyProductQuantityTableMap::COL_FK_PRODUCT;
    }
}
