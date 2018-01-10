<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductCategoryFilterStorage\Storage;

use Generated\Shared\Transfer\ProductCategoryFilterStorageTransfer;
use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Spryker\Client\ProductCategoryFilterStorage\Dependency\Client\ProductCategoryFilterStorageToStorageInterface;
use Spryker\Client\ProductCategoryFilterStorage\Dependency\Service\ProductCategoryFilterStorageToSynchronizationServiceInterface;
use Spryker\Shared\Kernel\Store;
use Spryker\Shared\ProductCategoryFilterStorage\ProductCategoryFilterStorageConfig;

class ProductCategoryFilterStorageReader implements ProductCategoryFilterStorageReaderInterface
{
    /**
     * @var \Spryker\Client\ProductCategoryFilterStorage\Dependency\Client\ProductCategoryFilterStorageToStorageInterface
     */
    protected $storageClient;

    /**
     * @var \Spryker\Client\ProductCategoryFilterStorage\Dependency\Service\ProductCategoryFilterStorageToSynchronizationServiceInterface
     */
    protected $synchronizationService;

    /**
     * @var \Spryker\Shared\Kernel\Store
     */
    protected $store;

    /**
     * @param \Spryker\Client\ProductCategoryFilterStorage\Dependency\Client\ProductCategoryFilterStorageToStorageInterface $storageClient
     * @param \Spryker\Client\ProductCategoryFilterStorage\Dependency\Service\ProductCategoryFilterStorageToSynchronizationServiceInterface $synchronizationService
     * @param \Spryker\Shared\Kernel\Store $store
     */
    public function __construct(ProductCategoryFilterStorageToStorageInterface $storageClient, ProductCategoryFilterStorageToSynchronizationServiceInterface $synchronizationService, Store $store)
    {
        $this->storageClient = $storageClient;
        $this->synchronizationService = $synchronizationService;
        $this->store = $store;
    }

    /**
     * @param int $idCategory
     *
     * @return \Generated\Shared\Transfer\ProductCategoryFilterStorageTransfer|null
     */
    public function getProductCategoryFilter($idCategory)
    {
        $key = $this->generateKey($idCategory);
        $productCategoryFilterData = $this->storageClient->get($key);

        if (!$productCategoryFilterData) {
            return null;
        }

        return (new ProductCategoryFilterStorageTransfer())->fromArray($productCategoryFilterData, true);
    }

    /**
     * @param int $resourceId
     *
     * @return string
     */
    protected function generateKey($resourceId)
    {
        $synchronizationDataTransfer = new SynchronizationDataTransfer();
        $synchronizationDataTransfer
            ->setStore($this->store->getStoreName())
            ->setReference($resourceId);

        return $this->synchronizationService->getStorageKeyBuilder(ProductCategoryFilterStorageConfig::PRODUCT_CATEGORY_FILTER_RESOURCE_NAME)->generateKey($synchronizationDataTransfer);
    }
}
