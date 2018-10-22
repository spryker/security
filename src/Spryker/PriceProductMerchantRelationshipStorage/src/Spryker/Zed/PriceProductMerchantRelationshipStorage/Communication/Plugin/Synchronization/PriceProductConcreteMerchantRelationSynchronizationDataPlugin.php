<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\Plugin\Synchronization;

use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Spryker\Shared\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageConstants;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageConfig;
use Spryker\Zed\SynchronizationExtension\Dependency\Plugin\SynchronizationDataRepositoryPluginInterface;

/**
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\PriceProductMerchantRelationshipStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\PriceProductMerchantRelationshipStorageCommunicationFactory getFactory()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepositoryInterface getRepository()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageConfig getConfig()
 */
class PriceProductConcreteMerchantRelationSynchronizationDataPlugin extends AbstractPlugin implements SynchronizationDataRepositoryPluginInterface
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
        return PriceProductMerchantRelationshipStorageConstants::PRICE_PRODUCT_CONCRETE_MERCHANT_RELATIONSHIP_RESOURCE_NAME;
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
        return PriceProductMerchantRelationshipStorageConfig::PRICE_PRODUCT_MERCHANT_RELATIONSHIP_SYNC_STORAGE_QUEUE;
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
        return $this->getConfig()->getPriceProductConcreteMerchantRelationSynchronizationPoolName();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $ids
     *
     * @return \Generated\Shared\Transfer\SynchronizationDataTransfer[]
     */
    public function getData(array $ids = [])
    {
        $data = [];
        $priceProductConcreteMerchantRelationshipStorageEntities = $this->findPriceProductConcreteMerchantRelationshipStorageEntities($ids);

        foreach ($priceProductConcreteMerchantRelationshipStorageEntities as $priceProductConcreteMerchantRelationshipStorageEntity) {
            $synchronizationDataTransfer = new SynchronizationDataTransfer();
            $synchronizationDataTransfer->setData($priceProductConcreteMerchantRelationshipStorageEntity->getData());
            $synchronizationDataTransfer->setKey($priceProductConcreteMerchantRelationshipStorageEntity->getKey());

            $data[] = $synchronizationDataTransfer;
        }

        return $data;
    }

    /**
     * @param array $ids
     *
     * @return array
     */
    protected function findPriceProductConcreteMerchantRelationshipStorageEntities(array $ids = [])
    {
        if (empty($ids)) {
            return $this->getRepository()
                ->findAllPriceProductConcreteMerchantRelationshipStorageEntities();
        }

        return $this->getRepository()
            ->findPriceProductConcreteMerchantRelationshipStorageEntitiesByIds($ids);
    }
}
