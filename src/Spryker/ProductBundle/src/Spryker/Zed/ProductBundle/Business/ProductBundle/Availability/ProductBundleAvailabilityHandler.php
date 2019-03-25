<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Business\ProductBundle\Availability;

use Generated\Shared\Transfer\StoreTransfer;
use Orm\Zed\Availability\Persistence\SpyAvailability;
use Orm\Zed\ProductBundle\Persistence\SpyProductBundle;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityInterface;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToStoreFacadeInterface;
use Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface;
use Spryker\Zed\ProductBundle\Dependency\Service\ProductBundleToUtilQuantityServiceInterface;
use Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface;
use Traversable;

class ProductBundleAvailabilityHandler implements ProductBundleAvailabilityHandlerInterface
{
    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface
     */
    protected $availabilityQueryContainer;

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityInterface
     */
    protected $availabilityFacade;

    /**
     * @var \Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface
     */
    protected $productBundleQueryContainer;

    /**
     * @var array
     */
    protected static $bundleItemEntityCache = [];

    /**
     * @var array
     */
    protected static $bundledItemEntityCache = [];

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Service\ProductBundleToUtilQuantityServiceInterface
     */
    protected $utilQuantityService;

    /**
     * @param \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface $availabilityQueryContainer
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityInterface $availabilityFacade
     * @param \Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface $productBundleQueryContainer
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\ProductBundle\Dependency\Service\ProductBundleToUtilQuantityServiceInterface $utilQuantityService
     */
    public function __construct(
        ProductBundleToAvailabilityQueryContainerInterface $availabilityQueryContainer,
        ProductBundleToAvailabilityInterface $availabilityFacade,
        ProductBundleQueryContainerInterface $productBundleQueryContainer,
        ProductBundleToStoreFacadeInterface $storeFacade,
        ProductBundleToUtilQuantityServiceInterface $utilQuantityService
    ) {
        $this->availabilityQueryContainer = $availabilityQueryContainer;
        $this->availabilityFacade = $availabilityFacade;
        $this->productBundleQueryContainer = $productBundleQueryContainer;
        $this->storeFacade = $storeFacade;
        $this->utilQuantityService = $utilQuantityService;
    }

    /**
     * @param string $bundledProductSku
     *
     * @return void
     */
    public function updateAffectedBundlesAvailability($bundledProductSku)
    {
        $bundleProducts = $this->getBundlesUsingProductBySku($bundledProductSku);

        foreach ($bundleProducts as $productBundleEntity) {
            $bundleItems = $this->getBundleItemsByIdProduct($productBundleEntity->getFkProduct());

            $bundleProductSku = $productBundleEntity->getSpyProductRelatedByFkProduct()
                ->getSku();

            $this->updateBundleProductAvailability($bundleItems, $bundleProductSku);
        }
    }

    /**
     * @param string $bundleProductSku
     *
     * @return void
     */
    public function updateBundleAvailability($bundleProductSku)
    {
        $bundleProductEntity = $this->findBundleProductEntityBySku($bundleProductSku);
        if ($bundleProductEntity === null) {
            return;
        }

        $bundleItems = $this->getBundleItemsByIdProduct($bundleProductEntity->getFkProduct());
        $this->updateBundleProductAvailability($bundleItems, $bundleProductSku);
    }

    /**
     * @param string $bundleProductSku
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return void
     */
    public function removeBundleAvailability($bundleProductSku, StoreTransfer $storeTransfer)
    {
        $this->availabilityFacade->saveProductAvailabilityForStore($bundleProductSku, 0.0, $storeTransfer);
    }

    /**
     * @param int $idConcreteProduct
     *
     * @return \Orm\Zed\ProductBundle\Persistence\SpyProductBundle[]|\Propel\Runtime\Collection\ObjectCollection
     */
    protected function getBundleItemsByIdProduct($idConcreteProduct)
    {
        if (!isset(static::$bundleItemEntityCache[$idConcreteProduct]) || count(static::$bundleItemEntityCache[$idConcreteProduct]) == 0) {
            static::$bundleItemEntityCache[$idConcreteProduct] = $this->productBundleQueryContainer
                ->queryBundleProduct($idConcreteProduct)
                ->find();
        }

        return static::$bundleItemEntityCache[$idConcreteProduct];
    }

    /**
     * @param string $bundledProductSku
     *
     * @return \Orm\Zed\ProductBundle\Persistence\SpyProductBundle[]|\Propel\Runtime\Collection\ObjectCollection
     */
    protected function getBundlesUsingProductBySku($bundledProductSku)
    {
        if (!isset(static::$bundledItemEntityCache[$bundledProductSku]) || count(static::$bundledItemEntityCache[$bundledProductSku]) == 0) {
            static::$bundledItemEntityCache[$bundledProductSku] = $this->productBundleQueryContainer
                ->queryBundledProductBySku($bundledProductSku)
                ->find();
        }

        return static::$bundledItemEntityCache[$bundledProductSku];
    }

    /**
     * @param array $bundleItems
     * @param string $bundleProductSku
     *
     * @return void
     */
    protected function updateBundleProductAvailability($bundleItems, $bundleProductSku)
    {
        $currentStoreTransfer = $this->storeFacade->getCurrentStore();

        $stores = $currentStoreTransfer->getStoresWithSharedPersistence();
        $stores[] = $this->storeFacade->getCurrentStore()->getName();

        foreach ($stores as $storeName) {
            $storeTransfer = $this->storeFacade->getStoreByName($storeName);
            $bundleAvailabilityQuantity = $this->calculateBundleQuantity($bundleItems, $storeTransfer);

            $this->availabilityFacade->saveProductAvailabilityForStore(
                $bundleProductSku,
                $bundleAvailabilityQuantity,
                $storeTransfer
            );
        }
    }

    /**
     * @param string $bundleProductSku
     *
     * @return \Orm\Zed\ProductBundle\Persistence\SpyProductBundle|null
     */
    protected function findBundleProductEntityBySku($bundleProductSku)
    {
        return $this->productBundleQueryContainer
            ->queryBundleProductBySku($bundleProductSku)
            ->findOne();
    }

    /**
     * @param string $bundledItemSku
     * @param int $idStore
     *
     * @return \Orm\Zed\Availability\Persistence\SpyAvailability|null
     */
    protected function findBundledItemAvailabilityEntityBySku($bundledItemSku, $idStore)
    {
        return $this->availabilityQueryContainer
            ->querySpyAvailabilityBySku($bundledItemSku, $idStore)
            ->findOne();
    }

    /**
     * @param \Traversable|\Orm\Zed\ProductBundle\Persistence\SpyProductBundle[] $bundleItems
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return int
     */
    protected function calculateBundleQuantity(Traversable $bundleItems, StoreTransfer $storeTransfer)
    {
        $bundleAvailabilityQuantity = 0;
        foreach ($bundleItems as $bundleItemEntity) {
            $bundledItemSku = $bundleItemEntity->getSpyProductRelatedByFkBundledProduct()
                ->getSku();

            $bundledProductAvailabilityEntity = $this->findBundledItemAvailabilityEntityBySku(
                $bundledItemSku,
                $storeTransfer->getIdStore()
            );

            if ($this->skipBundledItem($bundledProductAvailabilityEntity)) {
                continue;
            }

            if ($this->isBundledItemUnavailable($bundledProductAvailabilityEntity)) {
                return 0;
            }

            $bundleAvailabilityQuantity = $this->calculateBundledItemQuantity(
                $bundledProductAvailabilityEntity,
                $bundleItemEntity,
                $bundleAvailabilityQuantity
            );
        }

        return $bundleAvailabilityQuantity;
    }

    /**
     * @param \Orm\Zed\Availability\Persistence\SpyAvailability|null $bundledProductAvailabilityEntity
     *
     * @return bool
     */
    protected function isBundledItemUnavailable(?SpyAvailability $bundledProductAvailabilityEntity)
    {
        if (!$bundledProductAvailabilityEntity) {
            return false;
        }

        $isBundledItemUnavailable = (
            $this->isQuantityEqual($bundledProductAvailabilityEntity->getQuantity(), 0)
            && !$bundledProductAvailabilityEntity->getIsNeverOutOfStock()
        );

        return $isBundledItemUnavailable;
    }

    /**
     * @param \Orm\Zed\Availability\Persistence\SpyAvailability|null $bundledProductAvailabilityEntity
     *
     * @return bool
     */
    protected function skipBundledItem(?SpyAvailability $bundledProductAvailabilityEntity)
    {
        if ($bundledProductAvailabilityEntity === null) {
            return false;
        }

        return $bundledProductAvailabilityEntity->getIsNeverOutOfStock();
    }

    /**
     * @param \Orm\Zed\Availability\Persistence\SpyAvailability|null $bundledProductAvailabilityEntity
     * @param \Orm\Zed\ProductBundle\Persistence\SpyProductBundle $bundleItemEntity
     * @param int $bundleAvailabilityQuantity
     *
     * @return int
     */
    protected function calculateBundledItemQuantity(
        ?SpyAvailability $bundledProductAvailabilityEntity,
        SpyProductBundle $bundleItemEntity,
        $bundleAvailabilityQuantity
    ) {
        if (!$bundledProductAvailabilityEntity) {
            return 0;
        }

        $bundledItemQuantity = (int)floor(
            $bundledProductAvailabilityEntity->getQuantity() / $bundleItemEntity->getQuantity()
        );

        if ($this->isMaxQuantity($bundleAvailabilityQuantity, $bundledItemQuantity)) {
            return $bundledItemQuantity;
        }

        return $bundleAvailabilityQuantity;
    }

    /**
     * @param int $bundleAvailabilityQuantity
     * @param int $bundledItemQuantity
     *
     * @return bool
     */
    protected function isMaxQuantity($bundleAvailabilityQuantity, $bundledItemQuantity)
    {
        return ($bundleAvailabilityQuantity > $bundledItemQuantity || $bundleAvailabilityQuantity === 0);
    }

    /**
     * @param float $firstQuantity
     * @param float $secondQuantity
     *
     * @return bool
     */
    public function isQuantityEqual(float $firstQuantity, float $secondQuantity): bool
    {
        return $this->utilQuantityService->isQuantityEqual($firstQuantity, $secondQuantity);
    }
}
