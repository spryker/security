<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductListStorage\Business\ProductListProductAbstractStorage;

use Generated\Shared\Transfer\ProductAbstractProductListStorageTransfer;
use Orm\Zed\ProductList\Persistence\Map\SpyProductListTableMap;
use Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage;
use Spryker\Zed\ProductListStorage\Dependency\Facade\ProductListStorageToProductListFacadeInterface;
use Spryker\Zed\ProductListStorage\Persistence\ProductListStorageRepositoryInterface;

class ProductListProductAbstractStorageWriter implements ProductListProductAbstractStorageWriterInterface
{
    /**
     * @var \Spryker\Zed\ProductListStorage\Dependency\Facade\ProductListStorageToProductListFacadeInterface
     */
    protected $productListFacade;

    /**
     * @var \Spryker\Zed\ProductListStorage\Persistence\ProductListStorageRepositoryInterface
     */
    protected $productListStorageRepository;

    /**
     * @var bool
     */
    protected $isSendingToQueue;

    /**
     * @param \Spryker\Zed\ProductListStorage\Dependency\Facade\ProductListStorageToProductListFacadeInterface $productListFacade
     * @param \Spryker\Zed\ProductListStorage\Persistence\ProductListStorageRepositoryInterface $productListStorageRepository
     * @param bool $isSendingToQueue
     */
    public function __construct(
        ProductListStorageToProductListFacadeInterface $productListFacade,
        ProductListStorageRepositoryInterface $productListStorageRepository,
        bool $isSendingToQueue
    ) {
        $this->productListFacade = $productListFacade;
        $this->productListStorageRepository = $productListStorageRepository;
        $this->isSendingToQueue = $isSendingToQueue;
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return void
     */
    public function publish(array $productAbstractIds): void
    {
        $productListBuffer = $this->productListFacade->getProductAbstractListsIdsByIdProductAbstractIn($productAbstractIds);

        $productAbstractProductListStorageEntities = $this->findProductAbstractProductListStorageEntities($productAbstractIds);
        $indexedProductAbstractProductListStorageEntities = $this->indexProductAbstractProductListStorageEntities($productAbstractProductListStorageEntities);
        foreach ($productAbstractIds as $idProductAbstract) {
            $productAbstractProductListStorageEntity = $this->getProductAbstractProductListStorageEntity($idProductAbstract, $indexedProductAbstractProductListStorageEntities);
            if ($this->saveProductAbstractProductListStorageEntity($idProductAbstract, $productAbstractProductListStorageEntity, $productListBuffer)) {
                unset($indexedProductAbstractProductListStorageEntities[$idProductAbstract]);
            }
        }

        $this->deleteProductAbstractProductListStorageEntities($indexedProductAbstractProductListStorageEntities);
    }

    /**
     * @param int $idProductAbstract
     * @param \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage $productAbstractProductListStorageEntity
     * @param array $productListBuffer
     *
     * @return bool
     */
    protected function saveProductAbstractProductListStorageEntity(
        int $idProductAbstract,
        SpyProductAbstractProductListStorage $productAbstractProductListStorageEntity,
        array $productListBuffer
    ): bool {
        $productAbstractProductListsStorageEntityTransfer = $this->getProductAbstractProductListsStorageTransfer($idProductAbstract, $productListBuffer);
        if ($productAbstractProductListsStorageEntityTransfer->getIdWhitelists() || $productAbstractProductListsStorageEntityTransfer->getIdBlacklists()) {
            $productAbstractProductListStorageEntity->setFkProductAbstract($idProductAbstract)
                ->setData($productAbstractProductListsStorageEntityTransfer->toArray())
                ->setIsSendingToQueue($this->isSendingToQueue)
                ->save();

            return true;
        }

        return false;
    }

    /**
     * @param int $idProductAbstract
     * @param array $productListBuffer
     *
     * @return \Generated\Shared\Transfer\ProductAbstractProductListStorageTransfer
     */
    protected function getProductAbstractProductListsStorageTransfer(
        int $idProductAbstract,
        array $productListBuffer
    ): ProductAbstractProductListStorageTransfer {
        $productAbstractProductListsStorageTransfer = new ProductAbstractProductListStorageTransfer();
        $productAbstractProductListsStorageTransfer->setIdProductAbstract($idProductAbstract)
            ->setIdBlacklists($this->findProductAbstractBlacklistIds($idProductAbstract, $productListBuffer))
            ->setIdWhitelists($this->findProductAbstractWhitelistIds($idProductAbstract, $productListBuffer));

        return $productAbstractProductListsStorageTransfer;
    }

    /**
     * @param int $idProductAbstract
     * @param array $productListBuffer
     *
     * @return int[]
     */
    protected function findProductAbstractBlacklistIds(int $idProductAbstract, array $productListBuffer): array
    {
        return $productListBuffer[$idProductAbstract][SpyProductListTableMap::COL_TYPE_BLACKLIST] ?? [];
    }

    /**
     * @param int $idProductAbstract
     * @param array $productListBuffer
     *
     * @return int[]
     */
    protected function findProductAbstractWhitelistIds(int $idProductAbstract, array $productListBuffer): array
    {
        return $productListBuffer[$idProductAbstract][SpyProductListTableMap::COL_TYPE_WHITELIST] ?? [];
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[]
     */
    protected function findProductAbstractProductListStorageEntities(array $productAbstractIds): array
    {
        return $this->productListStorageRepository->findProductAbstractProductListStorageEntities($productAbstractIds);
    }

    /**
     * @param \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[] $productAbstractProductListStorageEntities
     *
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[]
     */
    protected function indexProductAbstractProductListStorageEntities(array $productAbstractProductListStorageEntities): array
    {
        $indexedProductAbstractProductListStorageEntities = [];

        foreach ($productAbstractProductListStorageEntities as $entity) {
            $indexedProductAbstractProductListStorageEntities[$entity->getFkProductAbstract()] = $entity;
        }

        return $indexedProductAbstractProductListStorageEntities;
    }

    /**
     * @param int $idProductAbstract
     * @param \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[] $indexedProductAbstractProductListStorageEntities
     *
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage
     */
    protected function getProductAbstractProductListStorageEntity(int $idProductAbstract, array $indexedProductAbstractProductListStorageEntities): SpyProductAbstractProductListStorage
    {
        if (isset($indexedProductAbstractProductListStorageEntities[$idProductAbstract])) {
            return $indexedProductAbstractProductListStorageEntities[$idProductAbstract];
        }

        return new SpyProductAbstractProductListStorage();
    }

    /**
     * @param \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[] $productAbstractProductListStorageEntities
     *
     * @return void
     */
    protected function deleteProductAbstractProductListStorageEntities(array $productAbstractProductListStorageEntities): void
    {
        foreach ($productAbstractProductListStorageEntities as $productAbstractProductListStorageEntity) {
            $productAbstractProductListStorageEntity->delete();
        }
    }
}
