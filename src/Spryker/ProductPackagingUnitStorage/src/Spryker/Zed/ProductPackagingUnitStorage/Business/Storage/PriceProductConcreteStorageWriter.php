<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Business\Storage;

use Generated\Shared\Transfer\PriceProductStorageTransfer;
use Orm\Zed\ProductPackagingUnitStorage\Persistence\SpyPriceProductConcreteStorage;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToPriceProductFacadeInterface;
use Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToStoreFacadeInterface;
use Spryker\Zed\ProductPackagingUnitStorage\Persistence\PriceProductStorageQueryContainer;
use Spryker\Zed\ProductPackagingUnitStorage\Persistence\PriceProductStorageQueryContainerInterface;

class PriceProductConcreteStorageWriter implements PriceProductConcreteStorageWriterInterface
{
    /**
     * @var \Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToPriceProductFacadeInterface
     */
    protected $priceProductFacade;

    /**
     * @var \Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\ProductPackagingUnitStorage\Persistence\PriceProductStorageQueryContainerInterface
     */
    protected $queryContainer;

    /**
     * @var bool
     */
    protected $isSendingToQueue = true;

    /**
     * @var int[] Keys are store ids, values are store names.
     */
    protected $storeNameMapBuffer;

    /**
     * @param \Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToPriceProductFacadeInterface $priceProductFacade
     * @param \Spryker\Zed\ProductPackagingUnitStorage\Dependency\Facade\PriceProductStorageToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\ProductPackagingUnitStorage\Persistence\PriceProductStorageQueryContainerInterface $queryContainer
     * @param bool $isSendingToQueue
     */
    public function __construct(
        PriceProductStorageToPriceProductFacadeInterface $priceProductFacade,
        PriceProductStorageToStoreFacadeInterface $storeFacade,
        PriceProductStorageQueryContainerInterface $queryContainer,
        $isSendingToQueue
    ) {
        $this->priceProductFacade = $priceProductFacade;
        $this->storeFacade = $storeFacade;
        $this->queryContainer = $queryContainer;
        $this->isSendingToQueue = $isSendingToQueue;
    }

    /**
     * @param array $productConcreteIds
     *
     * @return void
     */
    public function publish(array $productConcreteIds)
    {
        $productAbstractIdMap = $this->getProductAbstractIdMap($productConcreteIds);
        $priceGroups = $this->getProductConcretePriceGroup($productAbstractIdMap);

        $priceProductConcreteStorageEntities = $this->findPriceProductConcreteStorageEntities($productConcreteIds);
        $priceProductConcreteStorageMap = $this->getPriceProductConcreteStorageMap($priceProductConcreteStorageEntities);

        $this->storeData($priceGroups, $priceProductConcreteStorageMap);
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return void
     */
    public function unpublish(array $productConcreteIds)
    {
        $priceProductConcreteStorageEntities = $this->findPriceProductConcreteStorageEntities($productConcreteIds);
        foreach ($priceProductConcreteStorageEntities as $priceProductConcreteStorageEntity) {
            $priceProductConcreteStorageEntity->delete();
        }
    }

    /**
     * @param array $priceGroups First level keys are product concrete ids, second level keys are store names, values are grouped prices.
     * @param array $priceProductConcreteStorageMap First level keys are product concrete ids, second level keys are store names, values are SpyPriceProductConcreteStorage objects
     *
     * @return void
     */
    protected function storeData(array $priceGroups, array $priceProductConcreteStorageMap)
    {
        foreach ($priceGroups as $idProductConcrete => $storePriceGroups) {
            foreach ($storePriceGroups as $storeName => $priceGroup) {
                $priceProductConcreteStorage = $this->getRelatedPriceProductConcreteStorageEntity(
                    $priceProductConcreteStorageMap,
                    $idProductConcrete,
                    $storeName
                );

                unset($priceProductConcreteStorageMap[$idProductConcrete][$storeName]);

                if ($this->hasProductConcretePrices($priceGroup)) {
                    $this->storePriceProduct(
                        $idProductConcrete,
                        $storeName,
                        $priceGroup,
                        $priceProductConcreteStorage
                    );

                    continue;
                }

                $this->deletePriceProduct($priceProductConcreteStorage);
            }
        }

        array_walk_recursive($priceProductConcreteStorageMap, function (SpyPriceProductConcreteStorage $priceProductConcreteStorageEntity) {
            $priceProductConcreteStorageEntity->delete();
        });
    }

    /**
     * @param array $priceProductConcreteStorageMap
     * @param int $idProductConcrete
     * @param string $storeName
     *
     * @return \Orm\Zed\ProductPackagingUnitStorage\Persistence\SpyPriceProductConcreteStorage
     */
    protected function getRelatedPriceProductConcreteStorageEntity($priceProductConcreteStorageMap, $idProductConcrete, $storeName)
    {
        if (isset($priceProductConcreteStorageMap[$idProductConcrete][$storeName])) {
            return $priceProductConcreteStorageMap[$idProductConcrete][$storeName];
        }

        return new SpyPriceProductConcreteStorage();
    }

    /**
     * @param array $priceGroup
     *
     * @return bool
     */
    protected function hasProductConcretePrices(array $priceGroup)
    {
        if ($priceGroup) {
            return true;
        }

        return false;
    }

    /**
     * @param int $idProductConcrete
     * @param string $storeName
     * @param array $priceGroup
     * @param \Orm\Zed\ProductPackagingUnitStorage\Persistence\SpyPriceProductConcreteStorage $priceProductConcreteStorageEntity
     *
     * @return void
     */
    protected function storePriceProduct(
        $idProductConcrete,
        $storeName,
        array $priceGroup,
        SpyPriceProductConcreteStorage $priceProductConcreteStorageEntity
    ) {
        $priceProductStorageTransfer = (new PriceProductStorageTransfer())
            ->setPrices($priceGroup);

        $priceProductConcreteStorageEntity
            ->setFkProduct($idProductConcrete)
            ->setStore($storeName)
            ->setData($priceProductStorageTransfer->toArray(true))
            ->setIsSendingToQueue($this->isSendingToQueue)
            ->save();
    }

    /**
     * @param \Orm\Zed\ProductPackagingUnitStorage\Persistence\SpyPriceProductConcreteStorage $priceProductConcreteStorageEntity
     *
     * @return void
     */
    protected function deletePriceProduct(SpyPriceProductConcreteStorage $priceProductConcreteStorageEntity)
    {
        if (!$priceProductConcreteStorageEntity->isNew()) {
            $priceProductConcreteStorageEntity->delete();
        }
    }

    /**
     * @param int[] $productAbstractIdMap Keys are product concrete ids, values are product abstract ids
     *
     * @return array First level keys are product concrete ids, second level keys are store names, values are grouped prices.
     */
    protected function getProductConcretePriceGroup(array $productAbstractIdMap)
    {
        $priceGroups = [];
        foreach ($productAbstractIdMap as $idProductConcrete => $idProductAbstract) {
            $productConcretePriceProductTransfers = $this->priceProductFacade->findProductConcretePrices($idProductConcrete, $idProductAbstract);
            foreach ($productConcretePriceProductTransfers as $priceProductTransfer) {
                $storeName = $this->getStoreNameById($priceProductTransfer->getMoneyValue()->getFkStore());
                $priceGroups[$idProductConcrete][$storeName][] = $priceProductTransfer;
            }

            foreach ($priceGroups[$idProductConcrete] as $storeName => $priceProductTransferCollection) {
                $priceGroups[$idProductConcrete][$storeName] = $this->priceProductFacade->groupPriceProductCollection(
                    $priceProductTransferCollection
                );
            }
        }

        return $priceGroups;
    }

    /**
     * @param \Orm\Zed\ProductPackagingUnitStorage\Persistence\SpyPriceProductConcreteStorage[] $priceProductConcreteStorageEntities
     *
     * @return array
     */
    protected function getPriceProductConcreteStorageMap(array $priceProductConcreteStorageEntities)
    {
        $priceProductConcreteStorageMap = [];
        foreach ($priceProductConcreteStorageEntities as $storageEntity) {
            $priceProductConcreteStorageMap[$storageEntity->getFkProduct()][$storageEntity->getStore()] = $storageEntity;
        }

        return $priceProductConcreteStorageMap;
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return int[] Keys are product concrete ids, values are product abstract ids
     */
    protected function getProductAbstractIdMap(array $productConcreteIds)
    {
        return $this->queryContainer
            ->queryProductAbstractIdsByProductConcreteIds($productConcreteIds)
            ->find()
            ->toKeyValue(PriceProductStorageQueryContainer::ID_PRODUCT_CONCRETE, PriceProductStorageQueryContainer::ID_PRODUCT_ABSTRACT);
    }

    /**
     * @param int $idStore
     *
     * @return string
     */
    protected function getStoreNameById($idStore)
    {
        if (!$this->storeNameMapBuffer) {
            $this->loadStoreNameMap();
        }

        return $this->storeNameMapBuffer[$idStore];
    }

    /**
     * @return void
     */
    protected function loadStoreNameMap()
    {
        $storeTransfers = $this->storeFacade->getAllStores();

        $this->storeNameMapBuffer = [];
        foreach ($storeTransfers as $storeTransfer) {
            $this->storeNameMapBuffer[$storeTransfer->getIdStore()] = $storeTransfer->getName();
        }
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return \Orm\Zed\ProductPackagingUnitStorage\Persistence\SpyPriceProductConcreteStorage[]
     */
    protected function findPriceProductConcreteStorageEntities(array $productConcreteIds)
    {
        return $this->queryContainer
            ->queryPriceConcreteStorageByProductIds($productConcreteIds)
            ->find()
            ->getArrayCopy();
    }
}
