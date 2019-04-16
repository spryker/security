<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Business\ProductBundle\Availability\PreCheck;

use ArrayObject;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\CartPreCheckResponseTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Orm\Zed\Availability\Persistence\SpyAvailability;
use Propel\Runtime\Collection\ObjectCollection;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityInterface;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToStoreFacadeInterface;
use Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface;
use Spryker\Zed\ProductBundle\Dependency\Service\ProductBundleToUtilQuantityServiceInterface;
use Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface;
use Spryker\Zed\ProductBundle\ProductBundleConfig;

class ProductBundleCartAvailabilityCheck extends BasePreCheck implements ProductBundleCartAvailabilityCheckInterface
{
    public const CART_PRE_CHECK_ITEM_AVAILABILITY_FAILED = 'cart.pre.check.availability.failed';
    public const CART_PRE_CHECK_ITEM_AVAILABILITY_EMPTY = 'cart.pre.check.availability.failed.empty';
    public const STOCK_TRANSLATION_PARAMETER = '%stock%';
    public const SKU_TRANSLATION_PARAMETER = '%sku%';

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface
     */
    protected $availabilityQueryContainer;

    /**
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToAvailabilityInterface $availabilityFacade
     * @param \Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface $productBundleQueryContainer
     * @param \Spryker\Zed\ProductBundle\Dependency\QueryContainer\ProductBundleToAvailabilityQueryContainerInterface $availabilityQueryContainer
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\ProductBundle\ProductBundleConfig $productBundleConfig
     * @param \Spryker\Zed\ProductBundle\Dependency\Service\ProductBundleToUtilQuantityServiceInterface $utilQuantityService
     */
    public function __construct(
        ProductBundleToAvailabilityInterface $availabilityFacade,
        ProductBundleQueryContainerInterface $productBundleQueryContainer,
        ProductBundleToAvailabilityQueryContainerInterface $availabilityQueryContainer,
        ProductBundleToStoreFacadeInterface $storeFacade,
        ProductBundleConfig $productBundleConfig,
        ProductBundleToUtilQuantityServiceInterface $utilQuantityService
    ) {
        parent::__construct(
            $availabilityFacade,
            $productBundleQueryContainer,
            $storeFacade,
            $productBundleConfig,
            $utilQuantityService
        );

        $this->availabilityQueryContainer = $availabilityQueryContainer;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function checkCartAvailability(CartChangeTransfer $cartChangeTransfer)
    {
        $cartPreCheckFailedItems = new ArrayObject();
        $itemsInCart = clone $cartChangeTransfer->getQuote()->getItems();

        $storeTransfer = $cartChangeTransfer->getQuote()->getStore();
        $storeTransfer->requireName();

        $storeTransfer = $this->storeFacade->getStoreByName($storeTransfer->getName());
        foreach ($cartChangeTransfer->getItems() as $itemTransfer) {
            $itemTransfer->requireSku()->requireQuantity();

            $messageTransfers = $this->checkItemAvailability($itemsInCart, $itemTransfer, $storeTransfer);
            $itemsInCart->append($itemTransfer);

            foreach ($messageTransfers as $messageTransfer) {
                $cartPreCheckFailedItems[] = $messageTransfer;
            }
        }

        return $this->createCartPreCheckResponseTransfer($cartPreCheckFailedItems);
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $items
     * @param string $sku
     *
     * @return float
     */
    protected function getAccumulatedItemQuantityForBundledProductsByGivenSku(ArrayObject $items, $sku)
    {
        $quantity = 0.0;

        foreach ($items as $itemTransfer) {
            if (!$itemTransfer->getRelatedBundleItemIdentifier()) {
                continue;
            }

            if ($itemTransfer->getSku() !== $sku) {
                continue;
            }

            $quantity = $this->sumQuantities($quantity, $itemTransfer->getQuantity());
        }

        return $quantity;
    }

    /**
     * @param float $stock
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\MessageTransfer
     */
    protected function createItemIsNotAvailableMessageTransfer($stock, $sku)
    {
        $translationKey = $this->getItemAvailabilityTranslationKey($stock);

        return $this->createCartMessageTransfer($stock, $translationKey, $sku);
    }

    /**
     * @param float $stock
     * @param string $translationKey
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\MessageTransfer
     */
    protected function createCartMessageTransfer($stock, $translationKey, $sku)
    {
        $messageTransfer = new MessageTransfer();
        $messageTransfer->setValue($translationKey);
        $messageTransfer->setParameters([
            static::SKU_TRANSLATION_PARAMETER => $sku,
            static::STOCK_TRANSLATION_PARAMETER => $stock,
        ]);

        return $messageTransfer;
    }

    /**
     * @param float $stock
     *
     * @return string
     */
    protected function getItemAvailabilityTranslationKey($stock)
    {
        $translationKey = static::CART_PRE_CHECK_ITEM_AVAILABILITY_FAILED;
        if ($stock <= 0) {
            $translationKey = static::CART_PRE_CHECK_ITEM_AVAILABILITY_EMPTY;
        }
        return $translationKey;
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return \Orm\Zed\Availability\Persistence\SpyAvailability|null
     */
    protected function findAvailabilityEntityBySku($sku, StoreTransfer $storeTransfer)
    {
        return $this->availabilityQueryContainer
            ->querySpyAvailabilityBySku($sku, $storeTransfer->getIdStore())
            ->findOne();
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\MessageTransfer[] $messages
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    protected function createCartPreCheckResponseTransfer(ArrayObject $messages)
    {
        return (new CartPreCheckResponseTransfer())
            ->setIsSuccess(count($messages) == 0)
            ->setMessages($messages);
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $itemsInCart
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return float
     */
    protected function calculateRegularItemAvailability(
        ItemTransfer $itemTransfer,
        ArrayObject $itemsInCart,
        StoreTransfer $storeTransfer
    ) {
        $itemAvailability = $this->availabilityFacade->calculateStockForProductWithStore(
            $itemTransfer->getSku(),
            $storeTransfer
        );

        $bundledItemsQuantity = $this->getAccumulatedItemQuantityForBundledProductsByGivenSku(
            $itemsInCart,
            $itemTransfer->getSku()
        );

        return $this->subtractQuantities($itemAvailability, $bundledItemsQuantity);
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $itemsInCart
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    protected function checkItemAvailability(
        ArrayObject $itemsInCart,
        ItemTransfer $itemTransfer,
        StoreTransfer $storeTransfer
    ) {
        $bundledProducts = $this->findBundledProducts($itemTransfer->getSku());
        $bundledProductsMessages = [];

        if (count($bundledProducts) > 0) {
            return $this->getUnavailableBundleItemsInCart($itemsInCart, $bundledProducts, $itemTransfer, $storeTransfer);
        }

        $regularItemAvailability = $this->checkRegularItemAvailability($itemsInCart, $itemTransfer, $storeTransfer);
        if ($regularItemAvailability) {
            $bundledProductsMessages[] = $regularItemAvailability;
        }

        return $bundledProductsMessages;
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $itemsInCart
     * @param \Orm\Zed\ProductBundle\Persistence\SpyProductBundle[]|\Propel\Runtime\ActiveRecord\ActiveRecordInterface[]|\Propel\Runtime\Collection\ObjectCollection $bundledProducts
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    protected function getUnavailableBundleItemsInCart(
        ArrayObject $itemsInCart,
        ObjectCollection $bundledProducts,
        ItemTransfer $itemTransfer,
        StoreTransfer $storeTransfer
    ) {
        $unavailableBundleItems = $this->getUnavailableBundleItems($itemsInCart, $bundledProducts, $itemTransfer, $storeTransfer);

        $availabilityEntity = $this->findAvailabilityEntityBySku($itemTransfer->getSku(), $storeTransfer);

        if ($availabilityEntity && $this->isUserRequestedMoreItemsThanInStock($itemTransfer, $availabilityEntity)
            && $this->isAllBundleItemsUnavailable($unavailableBundleItems, $bundledProducts)) {
            $bundleAvailabilityErrorMessage = $this->createItemIsNotAvailableMessageTransfer(
                $availabilityEntity->getQuantity(),
                $itemTransfer->getSku()
            );

            return [
                $bundleAvailabilityErrorMessage,
            ];
        }

        return $this->createMessageTransfersForUnavailableBundleItems($unavailableBundleItems);
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Orm\Zed\Availability\Persistence\SpyAvailability $availabilityEntity
     *
     * @return bool
     */
    protected function isUserRequestedMoreItemsThanInStock(ItemTransfer $itemTransfer, SpyAvailability $availabilityEntity): bool
    {
        return $itemTransfer->getQuantity() > $availabilityEntity->getQuantity();
    }

    /**
     * @param array $unavailableBundleItems
     * @param \Orm\Zed\ProductBundle\Persistence\SpyProductBundle[]|\Propel\Runtime\ActiveRecord\ActiveRecordInterface[]|\Propel\Runtime\Collection\ObjectCollection $bundledProducts
     *
     * @return bool
     */
    protected function isAllBundleItemsUnavailable(array $unavailableBundleItems, ObjectCollection $bundledProducts): bool
    {
        return count($unavailableBundleItems) === count($bundledProducts);
    }

    /**
     * @param array $unavailableBundleItems
     *
     * @return \Generated\Shared\Transfer\MessageTransfer[]
     */
    protected function createMessageTransfersForUnavailableBundleItems(array $unavailableBundleItems): array
    {
        $unavailableBundleItemsMessages = [];

        foreach ($unavailableBundleItems as $unavailableBundleItem) {
            $unavailableBundleItemsMessages[] = (new MessageTransfer())
                ->setValue(static::ERROR_BUNDLE_ITEM_UNAVAILABLE_TRANSLATION_KEY)
                ->setParameters($unavailableBundleItem);
        }

        return $unavailableBundleItemsMessages;
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $itemsInCart
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return \Generated\Shared\Transfer\MessageTransfer|null
     */
    protected function checkRegularItemAvailability($itemsInCart, ItemTransfer $itemTransfer, StoreTransfer $storeTransfer)
    {
        if ($this->checkIfItemIsSellable($itemsInCart, $itemTransfer->getSku(), $storeTransfer, $itemTransfer->getQuantity())) {
            return null;
        }

        $availability = $this->calculateRegularItemAvailability($itemTransfer, $itemsInCart, $storeTransfer);

        return $this->createItemIsNotAvailableMessageTransfer($availability, $itemTransfer->getSku());
    }
}
