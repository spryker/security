<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductQuantity\Business\Model\Validator;

use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\CartPreCheckResponseTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\SpyProductQuantityEntityTransfer;
use Spryker\Zed\ProductQuantity\Business\Model\ProductQuantityReaderInterface;

class ProductQuantityRestrictionValidator implements ProductQuantityRestrictionValidatorInterface
{
    protected const ERROR_QUANTITY_MIN_NOT_FULFILLED = 'cart.pre.check.quantity.min.failed';
    protected const ERROR_QUANTITY_MAX_NOT_FULFILLED = 'cart.pre.check.quantity.max.failed';
    protected const ERROR_QUANTITY_INTERVAL_NOT_FULFILLED = 'cart.pre.check.quantity.interval.failed';

    protected const RESTRICTION_MIN = 'min';
    protected const RESTRICTION_MAX = 'max';
    protected const RESTRICTION_INTERVAL = 'interval';

    /**
     * @var \Spryker\Zed\ProductQuantity\Business\Model\ProductQuantityReaderInterface
     */
    protected $productQuantityReader;

    /**
     * @param \Spryker\Zed\ProductQuantity\Business\Model\ProductQuantityReaderInterface $productQuantityReader
     */
    public function __construct(ProductQuantityReaderInterface $productQuantityReader)
    {
        $this->productQuantityReader = $productQuantityReader;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function validateItemAddition(CartChangeTransfer $cartChangeTransfer): CartPreCheckResponseTransfer
    {
        $responseTransfer = (new CartPreCheckResponseTransfer())->setIsSuccess(true);

        $cartQuantityMap = $this->getItemAddCartQuantityMap($cartChangeTransfer);
        $productQuantityEntityMap = $this->getProductQuantityEntityMap($cartChangeTransfer);

        foreach ($cartQuantityMap as $productSku => $productQuantity) {
            $this->validateItem($productSku, $productQuantity, $productQuantityEntityMap[$productSku], $responseTransfer);
        }

        return $responseTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function validateItemRemoval(CartChangeTransfer $cartChangeTransfer): CartPreCheckResponseTransfer
    {
        $responseTransfer = new CartPreCheckResponseTransfer();

        $cartQuantityMap = $this->getItemRemoveCartQuantityMap($cartChangeTransfer);
        $productQuantityEntityMap = $this->getProductQuantityEntityMap($cartChangeTransfer);

        foreach ($cartQuantityMap as $productSku => $productQuantity) {
            $this->validateItem($productSku, $productQuantity, $productQuantityEntityMap[$productSku], $responseTransfer);
        }

        return $responseTransfer;
    }

    /**
     * @param string $sku
     * @param int $quantity
     * @param \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer $productQuantityEntity
     * @param \Generated\Shared\Transfer\CartPreCheckResponseTransfer $responseTransfer
     *
     * @return void
     */
    protected function validateItem(string $sku, int $quantity, SpyProductQuantityEntityTransfer $productQuantityEntity, CartPreCheckResponseTransfer $responseTransfer): void
    {
        $min = $productQuantityEntity->getQuantityMin();
        $max = $productQuantityEntity->getQuantityMax();
        $interval = $productQuantityEntity->getQuantityInterval();

        if ($quantity !== 0 && $quantity < $min) {
            $this->addViolation(static::ERROR_QUANTITY_MIN_NOT_FULFILLED, $sku, $min, $quantity, $responseTransfer);
        }

        if ($max !== null && $quantity > $max) {
            $this->addViolation(static::ERROR_QUANTITY_MAX_NOT_FULFILLED, $sku, $max, $quantity, $responseTransfer);
        }

        if (($quantity - $min) % $interval !== 0) {
            $this->addViolation(static::ERROR_QUANTITY_INTERVAL_NOT_FULFILLED, $sku, $interval, $quantity, $responseTransfer);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return int[] Keys are product SKUs, values are product quantities as 'quote.quantity + change.quantity'
     */
    protected function getItemAddCartQuantityMap(CartChangeTransfer $cartChangeTransfer): array
    {
        $quoteQuantityMap = $this->getQuoteQuantityMap($cartChangeTransfer);

        $cartQuantityMap = [];
        foreach ($cartChangeTransfer->getItems() as $itemTransfer) {
            $productSku = $itemTransfer->getSku();
            $cartQuantityMap[$productSku] = $itemTransfer->getQuantity();

            if (isset($quoteQuantityMap[$productSku])) {
                $cartQuantityMap[$productSku] += $quoteQuantityMap[$productSku];
            }
        }

        return $cartQuantityMap;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return int[] Keys are product SKUs, values are product quantities as 'quote.quantity - change.quantity'
     */
    protected function getItemRemoveCartQuantityMap(CartChangeTransfer $cartChangeTransfer): array
    {
        $quoteQuantityMap = $this->getQuoteQuantityMap($cartChangeTransfer);

        $cartQuantityMap = [];
        foreach ($cartChangeTransfer->getItems() as $itemTransfer) {
            $productSku = $itemTransfer->getSku();
            $cartQuantityMap[$productSku] = -$itemTransfer->getQuantity();

            if (isset($quoteQuantityMap[$productSku])) {
                $cartQuantityMap[$productSku] += $quoteQuantityMap[$productSku];
            }
        }

        return $cartQuantityMap;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return array
     */
    protected function getQuoteQuantityMap(CartChangeTransfer $cartChangeTransfer): array
    {
        $quoteQuantityMap = [];
        foreach ($cartChangeTransfer->getQuote()->getItems() as $itemTransfer) {
            $quoteQuantityMap[$itemTransfer->getSku()] = $itemTransfer->getQuantity();
        }

        return $quoteQuantityMap;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer[] Keys are product SKUs.
     */
    protected function getProductQuantityEntityMap(CartChangeTransfer $cartChangeTransfer): array
    {
        $skus = $this->getChangedSkus($cartChangeTransfer);
        $productQuantityEntities = $this->productQuantityReader->findProductQuantityEntitiesByProductSku($skus);

        $productQuantityEntityMap = $this->mapProductQuantityEntitiesBySku($productQuantityEntities);
        $productQuantityEntityMap = $this->replaceMissingSkus($productQuantityEntityMap, $skus);

        return $productQuantityEntityMap;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return string[]
     */
    protected function getChangedSkus(CartChangeTransfer $cartChangeTransfer): array
    {
        $skus = [];
        foreach ($cartChangeTransfer->getItems() as $itemTransfer) {
            $skus[] = $itemTransfer->getSku();
        }

        return $skus;
    }

    /**
     * @return \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer
     */
    protected function getDefaultProductQuantityEntity()
    {
        return (new SpyProductQuantityEntityTransfer())
            ->setQuantityInterval(1)
            ->setQuantityMin(1);
    }

    /**
     * @param \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer[] $productQuantityEntityMap
     * @param string[] $requiredSkus
     *
     * @return \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer[]
     */
    protected function replaceMissingSkus($productQuantityEntityMap, $requiredSkus)
    {
        $defaultProductQuantityEntity = $this->getDefaultProductQuantityEntity();

        foreach ($requiredSkus as $sku) {
            if (isset($productQuantityEntityMap[$sku])) {
                continue;
            }

            $productQuantityEntityMap[$sku] = $defaultProductQuantityEntity;
        }

        return $productQuantityEntityMap;
    }

    /**
     * @param \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer[] $productQuantityEntities
     *
     * @return \Generated\Shared\Transfer\SpyProductQuantityEntityTransfer[]
     */
    protected function mapProductQuantityEntitiesBySku(array $productQuantityEntities)
    {
        $productQuantityEntityMap = [];
        foreach ($productQuantityEntities as $productQuantityEntity) {
            $productQuantityEntityMap[$productQuantityEntity->getProduct()->getSku()] = $productQuantityEntity;
        }

        return $productQuantityEntityMap;
    }

    /**
     * @param string $message
     * @param string $sku
     * @param int $restrictionValue
     * @param int $actualValue
     * @param \Generated\Shared\Transfer\CartPreCheckResponseTransfer $responseTransfer
     *
     * @return void
     */
    protected function addViolation(string $message, string $sku, int $restrictionValue, int $actualValue, CartPreCheckResponseTransfer $responseTransfer): void
    {
        $responseTransfer->setIsSuccess(false);
        $responseTransfer->addMessage(
            (new MessageTransfer())
                ->setValue($message)
                ->setParameters(['%sku%' => $sku, '%restrictionValue%' => $restrictionValue, '%actualValue%' => $actualValue])
        );
    }
}
