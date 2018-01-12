<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\CategoryStorage\Storage;

use Generated\Shared\Transfer\CategoryTreeStorageTransfer;
use Generated\Shared\Transfer\SynchronizationDataTransfer;
use Spryker\Client\CategoryStorage\Dependency\Client\CategoryStorageToStorageInterface;
use Spryker\Client\CategoryStorage\Dependency\Service\CategoryStorageToSynchronizationServiceInterface;
use Spryker\Shared\CategoryStorage\CategoryStorageConstants;
use Spryker\Shared\Kernel\Store;

class CategoryTreeStorageReader implements CategoryTreeStorageReaderInterface
{
    /**
     * @var \Spryker\Client\CategoryStorage\Dependency\Client\CategoryStorageToStorageInterface
     */
    protected $storageClient;

    /**
     * @var \Spryker\Client\CategoryStorage\Dependency\Service\CategoryStorageToSynchronizationServiceInterface
     */
    protected $synchronizationService;

    /**
     * @param \Spryker\Client\CategoryStorage\Dependency\Client\CategoryStorageToStorageInterface $storageClient
     * @param \Spryker\Client\CategoryStorage\Dependency\Service\CategoryStorageToSynchronizationServiceInterface $synchronizationService
     */
    public function __construct(CategoryStorageToStorageInterface $storageClient, CategoryStorageToSynchronizationServiceInterface $synchronizationService)
    {
        $this->storageClient = $storageClient;
        $this->synchronizationService = $synchronizationService;
    }

    /**
     * @param string $locale
     *
     * @return \Generated\Shared\Transfer\CategoryNodeStorageTransfer[]
     */
    public function getCategories($locale)
    {
        $categoryTreeKey = $this->generateKey($locale);
        $categories = $this->storageClient->get($categoryTreeKey);
        if (!$categories) {
            return [];
        }

        $categoryTreeStorageTransfer = new CategoryTreeStorageTransfer();
        $categoryTreeStorageTransfer->fromArray($categories, true);

        return $categoryTreeStorageTransfer->getCategoryNodesStorage();
    }

    /**
     * @param string $locale
     *
     * @return string
     */
    protected function generateKey($locale)
    {
        $store = Store::getInstance()->getStoreName();

        $synchronizationDataTransfer = new SynchronizationDataTransfer();
        $synchronizationDataTransfer->setStore($store);
        $synchronizationDataTransfer->setLocale($locale);

        return $this->synchronizationService->getStorageKeyBuilder(CategoryStorageConstants::CATEGORY_TREE_RESOURCE_NAME)->generateKey($synchronizationDataTransfer);
    }
}
