<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductStorage\Communication\Plugin\Synchronization;

use Orm\Zed\PriceProductStorage\Persistence\SpyPriceProductAbstractStorageQuery;
use Spryker\Shared\PriceProductStorage\PriceProductStorageConstants;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\SynchronizationExtension\Dependency\Plugin\SynchronizationDataQueryContainerPluginInterface;

/**
 * @method \Spryker\Zed\PriceProductStorage\Persistence\PriceProductStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\PriceProductStorage\Business\PriceProductStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\PriceProductStorage\Communication\PriceProductStorageCommunicationFactory getFactory()
 */
class PriceProductAbstractSynchronizationDataPlugin extends AbstractPlugin implements SynchronizationDataQueryContainerPluginInterface
{
    /**
     * Specification:
     *  - Returns the resource name of the storage or search module
     *
     * @api
     *
     * @return string
     */
    public function getResourceName(): string
    {
        return PriceProductStorageConstants::PRICE_ABSTRACT_RESOURCE_NAME;
    }

    /**
     * Specification:
     *  - Returns true if this entity has multi-store concept
     *
     * @api
     *
     * @return bool
     */
    public function hasStore(): bool
    {
        return true;
    }

    /**
     * Specification:
     *  - Returns array of storage or search synchronized data, provided $ids parameter
     *    will limit the result
     *
     * @api
     *
     * @param int[] $ids
     *
     * @return \Orm\Zed\PriceProductStorage\Persistence\SpyPriceProductAbstractStorageQuery
     */
    public function queryData($ids = []): SpyPriceProductAbstractStorageQuery
    {
        $query = $this->getQueryContainer()->queryPriceAbstractStorageByPriceAbstractIds($ids);

        if (empty($ids)) {
            $query->clear();
        }

        return $query;
    }

    /**
     * Specification:
     *  - Returns array of configuration parameter which needed for Redis or Elasticsearch
     *
     * @api
     *
     * @return array
     */
    public function getParams(): array
    {
        return [];
    }

    /**
     * Specification:
     *  - Returns synchronization queue name
     *
     * @api
     *
     * @return string
     */
    public function getQueueName(): string
    {
        return PriceProductStorageConstants::PRICE_SYNC_STORAGE_QUEUE;
    }

    /**
     * Specification:
     *  - Returns synchronization queue pool name for broadcasting messages
     *
     * @api
     *
     * @return string|null
     */
    public function getSynchronizationQueuePoolName(): ?string
    {
        return $this->getFactory()->getConfig()->getPriceProductAbstractSynchronizationPoolName();
    }
}
