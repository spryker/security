<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Business\ProductBundle\Cart;

use ArrayObject;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\PriceProductFilterTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\ProductOptionTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Orm\Zed\ProductBundle\Persistence\SpyProductBundle;
use OutOfBoundsException;
use Propel\Runtime\Collection\ObjectCollection;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToLocaleInterface;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceInterface;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceProductFacadeInterface;
use Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductInterface;
use Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface;

class ProductBundleCartExpander implements ProductBundleCartExpanderInterface
{
    const BUNDLE_IDENTIFIER_DELIMITER = '_';

    /**
     * @var \Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface
     */
    protected $productBundleQueryContainer;

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceProductFacadeInterface
     */
    protected $priceProductFacade;

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductInterface
     */
    protected $productFacade;

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToLocaleInterface
     */
    protected $localeFacade;

    /**
     * @var \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceInterface
     */
    protected $priceFacade;

    /**
     * @var array
     */
    protected static $productConcreteCache = [];

    /**
     * @var array
     */
    protected static $localizedProductNameCache = [];

    /**
     * @var array
     */
    protected static $productPriceCache = [];

    /**
     * @param \Spryker\Zed\ProductBundle\Persistence\ProductBundleQueryContainerInterface $productBundleQueryContainer
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceProductFacadeInterface $priceProductFacade
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToProductInterface $productFacade
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToLocaleInterface $localeFacade
     * @param \Spryker\Zed\ProductBundle\Dependency\Facade\ProductBundleToPriceInterface $priceFacade
     */
    public function __construct(
        ProductBundleQueryContainerInterface $productBundleQueryContainer,
        ProductBundleToPriceProductFacadeInterface $priceProductFacade,
        ProductBundleToProductInterface $productFacade,
        ProductBundleToLocaleInterface $localeFacade,
        ProductBundleToPriceInterface $priceFacade
    ) {
        $this->productBundleQueryContainer = $productBundleQueryContainer;
        $this->priceProductFacade = $priceProductFacade;
        $this->productFacade = $productFacade;
        $this->localeFacade = $localeFacade;
        $this->priceFacade = $priceFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function expandBundleItems(CartChangeTransfer $cartChangeTransfer)
    {
        $cartChangeTransfer->requireQuote()
            ->requireItems();

        $cartChangeItems = new ArrayObject();
        $quoteTransfer = $cartChangeTransfer->getQuote();

        foreach ($cartChangeTransfer->getItems() as $itemTransfer) {
            if ($itemTransfer->getRelatedBundleItemIdentifier()) {
                $cartChangeItems->append($itemTransfer);
                continue;
            }

            $itemTransfer->requireId()->requireQuantity();
            $this->requirePriceByMode($itemTransfer, $quoteTransfer->getPriceMode());

            $bundledProducts = $this->findBundledItemsByIdProductConcrete($itemTransfer->getId());

            if ($bundledProducts->count() == 0) {
                $cartChangeItems->append($itemTransfer);
                continue;
            };

            $addToCartItems = $this->buildBundle($itemTransfer, $quoteTransfer, $bundledProducts);

            foreach ($addToCartItems as $bundledItemTransfer) {
                $cartChangeItems->append($bundledItemTransfer);
            }
        }

        $cartChangeTransfer->setItems($cartChangeItems);
        $cartChangeTransfer->setQuote($quoteTransfer);

        return $cartChangeTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param \Propel\Runtime\Collection\ObjectCollection $bundledProducts
     *
     * @return array
     */
    protected function buildBundle(
        ItemTransfer $itemTransfer,
        QuoteTransfer $quoteTransfer,
        ObjectCollection $bundledProducts
    ) {
        $addToCartItems = [];
        $quantity = $itemTransfer->getQuantity();

        $productOptions = $itemTransfer->getProductOptions();
        $priceMode = $quoteTransfer->getPriceMode();
        $currencyIsoCode = $quoteTransfer->getCurrency()->getCode();
        for ($i = 0; $i < $quantity; $i++) {
            $bundleItemTransfer = new ItemTransfer();
            $bundleItemTransfer->fromArray($itemTransfer->toArray(), true);
            $bundleItemTransfer->setQuantity(1);

            $bundleItemIdentifier = $this->buildBundleIdentifier($bundleItemTransfer);
            $bundleItemTransfer->setBundleItemIdentifier($bundleItemIdentifier);

            $this->setGroupKey($itemTransfer, $bundleItemTransfer);

            $quoteTransfer->addBundleItem($bundleItemTransfer);

            $bundledItems = $this->createBundledItemsTransferCollection(
                $bundledProducts,
                $bundleItemIdentifier,
                $priceMode,
                $currencyIsoCode
            );

            $lastBundledItemTransfer = $bundledItems[count($bundledItems) - 1];
            $lastBundledItemTransfer->setProductOptions($productOptions);

            $this->distributeBundleUnitPrice(
                $bundledItems,
                $this->getPriceByPriceMode($itemTransfer, $priceMode),
                $quoteTransfer->getPriceMode()
            );

            $addToCartItems = array_merge($addToCartItems, $bundledItems);
        }

        return $addToCartItems;
    }

    /**
     * @param array $options
     *
     * @return array
     */
    protected function sortOptions(array $options)
    {
        usort(
            $options,
            function (ProductOptionTransfer $productOptionLeft, ProductOptionTransfer $productOptionRight) {
                return ($productOptionLeft->getSku() < $productOptionRight->getSku()) ? -1 : 1;
            }
        );

        return $options;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductOptionTransfer[] $sortedProductOptions
     *
     * @return string
     */
    protected function combineOptionParts(array $sortedProductOptions)
    {
        $groupKeyPart = [];
        foreach ($sortedProductOptions as $productOptionTransfer) {
            if (!$productOptionTransfer->getSku()) {
                continue;
            }
            $groupKeyPart[] = $productOptionTransfer->getSku();
        }

        return implode('_', $groupKeyPart);
    }

    /**
     * @param \Propel\Runtime\Collection\ObjectCollection $bundledProducts
     * @param string $bundleItemIdentifier
     * @param string $priceMode
     * @param string $currencyIsoCode
     *
     * @return array
     */
    protected function createBundledItemsTransferCollection(ObjectCollection $bundledProducts, $bundleItemIdentifier, $priceMode, $currencyIsoCode)
    {
        $bundledItems = [];
        foreach ($bundledProducts as $index => $productBundleEntity) {
            $quantity = $productBundleEntity->getQuantity();
            for ($i = 0; $i < $quantity; $i++) {
                $bundledItems[] = $this->createBundledItemTransfer(
                    $productBundleEntity,
                    $bundleItemIdentifier,
                    $priceMode,
                    $currencyIsoCode
                );
            }
        }
        return $bundledItems;
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return string
     */
    protected function buildBundleIdentifier(ItemTransfer $itemTransfer)
    {
        $itemTransfer->requireSku();

        return $itemTransfer->getSku() . static::BUNDLE_IDENTIFIER_DELIMITER . uniqid(true);
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $bundledProducts
     * @param int $bundleUnitPrice
     * @param string $priceMode
     *
     * @throws \OutOfBoundsException
     *
     * @return void
     */
    protected function distributeBundleUnitPrice(array $bundledProducts, $bundleUnitPrice, $priceMode)
    {
        $totalBundledItemUnitGrossPrice = $this->calculateBundleTotalUnitPrice($bundledProducts, $priceMode);
        if ($totalBundledItemUnitGrossPrice <= 0) {
            return;
        }

        $roundingError = 0;
        $priceRatio = $bundleUnitPrice / $totalBundledItemUnitGrossPrice;
        foreach ($bundledProducts as $itemTransfer) {
            $this->requirePriceByMode($itemTransfer, $priceMode);

            $unitPrice = $this->getPriceByPriceMode($itemTransfer, $priceMode);
            if ($unitPrice <= 0) {
                throw new OutOfBoundsException("Invalid price given, natural integer expected.");
            }

            $priceBeforeRound = ($unitPrice * $priceRatio) + $roundingError;
            $priceRounded = (int)round($priceBeforeRound);
            $roundingError = $priceBeforeRound - $priceRounded;

            $this->setPrice($itemTransfer, $priceRounded, $priceMode);
        }
    }

    /**
     * @param \Orm\Zed\ProductBundle\Persistence\SpyProductBundle $bundleProductEntity
     * @param string $bundleItemIdentifier
     * @param string $priceMode
     * @param string $currencyIsoCode
     *
     * @return \Generated\Shared\Transfer\ItemTransfer
     */
    protected function createBundledItemTransfer(
        SpyProductBundle $bundleProductEntity,
        $bundleItemIdentifier,
        $priceMode,
        $currencyIsoCode
    ) {
        $bundledConcreteProductEntity = $bundleProductEntity->getSpyProductRelatedByFkBundledProduct();

        $productConcreteTransfer = $this->getProductConcreteTransfer(
            $bundledConcreteProductEntity->getSku()
        );

        $localizedProductName = $this->getLocalizedProductName(
            $productConcreteTransfer,
            $this->localeFacade->getCurrentLocale()
        );

        $unitPrice = $this->getProductPrice(
            $bundledConcreteProductEntity->getSku(),
            $currencyIsoCode,
            $priceMode
        );

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setId($productConcreteTransfer->getIdProductConcrete())
            ->setSku($productConcreteTransfer->getSku())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setAbstractSku($productConcreteTransfer->getAbstractSku())
            ->setName($localizedProductName)
            ->setQuantity(1)
            ->setRelatedBundleItemIdentifier($bundleItemIdentifier);

        $this->setPrice($itemTransfer, $unitPrice, $priceMode);

        return $itemTransfer;
    }

    /**
     * @param string $sku
     * @param string $currencyIsoCode
     * @param string $priceMode
     *
     * @return int
     */
    protected function getProductPrice($sku, $currencyIsoCode, $priceMode)
    {
        if (!isset(static::$productPriceCache[$sku])) {
            $priceFilterTransfer = $this->createPriceProductFilterTransfer($sku, $currencyIsoCode, $priceMode);
            static::$productPriceCache[$sku] = $this->priceProductFacade->findPriceFor($priceFilterTransfer);
        }

         return static::$productPriceCache[$sku];
    }

    /**
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    protected function getProductConcreteTransfer($sku)
    {
        if (!isset(static::$productConcreteCache[$sku])) {
            static::$productConcreteCache[$sku] = $this->productFacade->getProductConcrete($sku);
        }

        return static::$productConcreteCache[$sku];
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     * @param \Generated\Shared\Transfer\LocaleTransfer $currentLocaleTransfer
     *
     * @return string
     */
    protected function getLocalizedProductName(
        ProductConcreteTransfer $productConcreteTransfer,
        LocaleTransfer $currentLocaleTransfer
    ) {

        $localeMapKey = $currentLocaleTransfer->getLocaleName() . $productConcreteTransfer->getIdProductConcrete();

        if (!isset(static::$localizedProductNameCache[$localeMapKey])) {
            static::$localizedProductNameCache[$localeMapKey] = $this->productFacade->getLocalizedProductConcreteName(
                $productConcreteTransfer,
                $this->localeFacade->getCurrentLocale()
            );
        }

        return static::$localizedProductNameCache[$localeMapKey];
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $bundledProducts
     * @param string $priceMode
     *
     * @return int
     */
    protected function calculateBundleTotalUnitPrice(array $bundledProducts, $priceMode)
    {
        $totalBundleItemAmount = (int)array_reduce($bundledProducts, function ($total, ItemTransfer $itemTransfer) use ($priceMode) {
            if ($priceMode === $this->priceFacade->getNetPriceModeIdentifier()) {
                $total += $itemTransfer->getUnitNetPrice();
            } else {
                $total += $itemTransfer->getUnitGrossPrice();
            }
            return $total;
        });

        return $totalBundleItemAmount;
    }

    /**
     * @param int $idProductConcrete
     *
     * @return mixed|mixed[]|\Orm\Zed\ProductBundle\Persistence\SpyProductBundle[]|\Propel\Runtime\ActiveRecord\ActiveRecordInterface[]|\Propel\Runtime\Collection\ObjectCollection|mixed
     */
    protected function findBundledItemsByIdProductConcrete($idProductConcrete)
    {
        return $this->productBundleQueryContainer
            ->queryBundleProduct($idProductConcrete)
            ->find();
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Generated\Shared\Transfer\ItemTransfer $bundleItemTransfer
     *
     * @return void
     */
    protected function setGroupKey(ItemTransfer $itemTransfer, ItemTransfer $bundleItemTransfer)
    {
        $options = (array)$itemTransfer->getProductOptions();
        if (count($options) === 0) {
            $bundleItemTransfer->setGroupKey($bundleItemTransfer->getSku());
            return;
        }

        $options = $this->sortOptions($options);
        $groupKey = $itemTransfer->getSku() . '_' . $this->combineOptionParts($options);
        $bundleItemTransfer->setGroupKey($groupKey);
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param int $unitPrice
     * @param string $priceMode
     *
     * @return void
     */
    protected function setPrice(ItemTransfer $itemTransfer, $unitPrice, $priceMode)
    {
        if ($priceMode === $this->priceFacade->getNetPriceModeIdentifier()) {
            $itemTransfer->setUnitNetPrice($unitPrice);
            return;
        }

        $itemTransfer->setUnitGrossPrice($unitPrice);
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param string $priceMode
     *
     * @return void
     */
    protected function requirePriceByMode(ItemTransfer $itemTransfer, $priceMode)
    {
        if ($priceMode === $this->priceFacade->getNetPriceModeIdentifier()) {
            $itemTransfer->requireUnitNetPrice();
            return;
        }

        $itemTransfer->requireUnitGrossPrice();
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param string $priceMode
     *
     * @return int
     */
    protected function getPriceByPriceMode(ItemTransfer $itemTransfer, $priceMode)
    {
        if ($priceMode === $this->priceFacade->getNetPriceModeIdentifier()) {
            return $itemTransfer->getUnitNetPrice();
        }

        return $itemTransfer->getUnitGrossPrice();
    }

    /**
     * @param string $sku
     * @param string $currencyIsoCode
     * @param string $priceMode
     *
     * @return \Generated\Shared\Transfer\PriceProductFilterTransfer
     */
    protected function createPriceProductFilterTransfer($sku, $currencyIsoCode, $priceMode)
    {
        return (new PriceProductFilterTransfer())
            ->setSku($sku)
            ->setCurrencyIsoCode($currencyIsoCode)
            ->setPriceMode($priceMode);
    }
}
