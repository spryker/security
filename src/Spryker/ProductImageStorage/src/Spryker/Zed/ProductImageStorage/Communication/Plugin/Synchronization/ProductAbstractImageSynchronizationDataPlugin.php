<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductImageStorage\Communication\Plugin\Synchronization;

use Orm\Zed\ProductImageStorage\Persistence\SpyProductAbstractImageStorageQuery;
use Spryker\Shared\ProductImageStorage\ProductImageStorageConfig;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\SynchronizationExtension\Dependency\Plugin\SynchronizationDataQueryContainerPluginInterface;

/**
 * @method \Spryker\Zed\ProductImageStorage\Persistence\ProductImageStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductImageStorage\Business\ProductImageStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductImageStorage\Communication\ProductImageStorageCommunicationFactory getFactory()
 */
class ProductAbstractImageSynchronizationDataPlugin extends AbstractPlugin implements SynchronizationDataQueryContainerPluginInterface
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
        return ProductImageStorageConfig::PRODUCT_ABSTRACT_IMAGE_RESOURCE_NAME;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return bool
     */
    public function hasStore(): bool
    {
        return false;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $ids
     *
     * @return \Orm\Zed\ProductImageStorage\Persistence\SpyProductAbstractImageStorageQuery
     */
    public function queryData($ids = []): SpyProductAbstractImageStorageQuery
    {
        $query = $this->getQueryContainer()->queryProductAbstractImageStorageByIds($ids);

        if (empty($ids)) {
            $query->clear();
        }

        return $query;
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getQueueName(): string
    {
        return ProductImageStorageConfig::PRODUCT_ABSTRACT_IMAGE_SYNC_STORAGE_QUEUE;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string|null
     */
    public function getSynchronizationQueuePoolName(): ?string
    {
        return $this->getFactory()->getConfig()->getProductImageSynchronizationPoolName();
    }
}
