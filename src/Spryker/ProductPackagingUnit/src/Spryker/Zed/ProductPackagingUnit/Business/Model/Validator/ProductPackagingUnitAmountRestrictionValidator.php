<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnit\Business\Model\Validator;

use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\CartPreCheckResponseTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\ProductPackagingUnitAmountTransfer;
use Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnit\ProductPackagingUnitReaderInterface;

class ProductPackagingUnitAmountRestrictionValidator implements ProductPackagingUnitAmountRestrictionValidatorInterface
{
    protected const ERROR_AMOUNT_MIN_NOT_FULFILLED = 'cart.pre.check.amount.min.failed';
    protected const ERROR_AMOUNT_MAX_NOT_FULFILLED = 'cart.pre.check.amount.max.failed';
    protected const ERROR_AMOUNT_INTERVAL_NOT_FULFILLED = 'cart.pre.check.amount.interval.failed';
    protected const ERROR_AMOUNT_IS_NOT_VARIABLE = 'cart.pre.check.amount.is_not_variable.failed';

    protected const PRODUCT_PACKAGING_UNIT_AMOUNT_DEFAULT_VALUES = [
        ProductPackagingUnitAmountTransfer::AMOUNT_INTERVAL => 1,
        ProductPackagingUnitAmountTransfer::AMOUNT_MIN => 1,
    ];

    /**
     * @var \Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnit\ProductPackagingUnitReaderInterface
     */
    protected $productPackagingUnitReader;

    /**
     * @param \Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnit\ProductPackagingUnitReaderInterface $productPackagingUnitReader
     */
    public function __construct(ProductPackagingUnitReaderInterface $productPackagingUnitReader)
    {
        $this->productPackagingUnitReader = $productPackagingUnitReader;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function validateItemAddition(CartChangeTransfer $cartChangeTransfer): CartPreCheckResponseTransfer
    {
        $responseTransfer = (new CartPreCheckResponseTransfer())->setIsSuccess(true);

        $this->validate($cartChangeTransfer, $responseTransfer);

        return $responseTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     * @param \Generated\Shared\Transfer\CartPreCheckResponseTransfer $responseTransfer
     *
     * @return void
     */
    protected function validate(CartChangeTransfer $cartChangeTransfer, CartPreCheckResponseTransfer $responseTransfer): void
    {
        $itemTransfers = $this->selectItemTransfersWithAmountSalesUnit($cartChangeTransfer);

        if (!$itemTransfers) {
            return;
        }

        $changedSkuMapByGroupKey = $this->getChangedSkuMap($itemTransfers);
        $cartAmountMapByGroupKey = $this->getItemAddCartAmountMap($itemTransfers, $cartChangeTransfer);
        $productPackagingUnitAmountTransferMapBySku = $this->getProductPackagingUnitAmountTransferMap($itemTransfers);

        foreach ($cartAmountMapByGroupKey as $productGroupKey => $cartAmount) {
            $productSku = $changedSkuMapByGroupKey[$productGroupKey];
            $this->validateItem($productSku, $cartAmount, $productPackagingUnitAmountTransferMapBySku[$productSku], $responseTransfer);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\ItemTransfer[]
     */
    protected function selectItemTransfersWithAmountSalesUnit(CartChangeTransfer $cartChangeTransfer): array
    {
        $packagingUnitItemTransfers = [];
        $itemTransfers = $cartChangeTransfer->getItems();

        foreach ($itemTransfers as $itemTransfer) {
            if (!$itemTransfer->getAmountSalesUnit()) {
                continue;
            }
            $packagingUnitItemTransfers[] = $itemTransfer;
        }

        return $packagingUnitItemTransfers;
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $itemTransfers
     *
     * @return string[]
     */
    protected function getChangedSkuMap(array $itemTransfers): array
    {
        $skuMap = [];

        foreach ($itemTransfers as $itemTransfer) {
            $skuMap[$itemTransfer->getGroupKey()] = $itemTransfer->getSku();
        }

        return $skuMap;
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $itemTransfers
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return int[]
     */
    protected function getItemAddCartAmountMap(array $itemTransfers, CartChangeTransfer $cartChangeTransfer): array
    {
        $quoteAmountMapByGroupKey = $this->getQuoteAmountMap($cartChangeTransfer);
        $cartAmountMap = [];

        foreach ($itemTransfers as $itemTransfer) {
            $productGroupKey = $itemTransfer->getGroupKey();
            $amountPerQuantity = $itemTransfer->getAmount() / $itemTransfer->getQuantity();
            $cartAmountMap[$productGroupKey] = (int)$amountPerQuantity;

            if (isset($quoteAmountMapByGroupKey[$productGroupKey])) {
                $cartAmountMap[$productGroupKey] += $quoteAmountMapByGroupKey[$productGroupKey];
            }
        }

        return $cartAmountMap;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return array
     */
    protected function getQuoteAmountMap(CartChangeTransfer $cartChangeTransfer): array
    {
        $quoteAmountMap = [];
        foreach ($cartChangeTransfer->getQuote()->getItems() as $itemTransfer) {
            $amountPerQuantity = $itemTransfer->getAmount() / $itemTransfer->getQuantity();
            $quoteAmountMap[$itemTransfer->getGroupKey()] = (int)$amountPerQuantity;
        }

        return $quoteAmountMap;
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $itemTransfers
     *
     * @return \Generated\Shared\Transfer\ProductPackagingUnitAmountTransfer[].
     */
    protected function getProductPackagingUnitAmountTransferMap(array $itemTransfers): array
    {
        $skus = $this->getChangedSkuMap($itemTransfers);

        $productPackagingUnitAmountTransferMap = $this->mapProductPackagingUnitAmountTransfersBySku($itemTransfers);
        $productPackagingUnitAmountTransferMap = $this->replaceMissingSkus($productPackagingUnitAmountTransferMap, $skus);

        return $productPackagingUnitAmountTransferMap;
    }

    /**
     * @param string $sku
     * @param int $amount
     * @param \Generated\Shared\Transfer\ProductPackagingUnitAmountTransfer $productPackagingUnitAmountTransfer
     * @param \Generated\Shared\Transfer\CartPreCheckResponseTransfer $responseTransfer
     *
     * @return void
     */
    protected function validateItem(string $sku, int $amount, ProductPackagingUnitAmountTransfer $productPackagingUnitAmountTransfer, CartPreCheckResponseTransfer $responseTransfer): void
    {
        $min = $productPackagingUnitAmountTransfer->getAmountMin();
        $max = $productPackagingUnitAmountTransfer->getAmountMax();
        $interval = $productPackagingUnitAmountTransfer->getAmountInterval();
        $defaultAmount = $productPackagingUnitAmountTransfer->getDefaultAmount();
        $isVariable = $productPackagingUnitAmountTransfer->getIsVariable();

        if ($amount != 0 && $amount < $min) {
            $this->addViolation(static::ERROR_AMOUNT_MIN_NOT_FULFILLED, $sku, $min, $amount, $responseTransfer);
        }

        if ($amount != 0 && $interval != null && ($amount - $min) % $interval != 0) {
            $this->addViolation(static::ERROR_AMOUNT_INTERVAL_NOT_FULFILLED, $sku, $interval, $amount, $responseTransfer);
        }

        if ($max != null && $amount > $max) {
            $this->addViolation(static::ERROR_AMOUNT_MAX_NOT_FULFILLED, $sku, $max, $amount, $responseTransfer);
        }

        if (!$isVariable && $amount != $defaultAmount) {
            $this->addViolation(static::ERROR_AMOUNT_IS_NOT_VARIABLE, $sku, $defaultAmount, $amount, $responseTransfer);
        }
    }

    /**
     * @param string $message
     * @param string $sku
     * @param float $restrictionValue
     * @param float $actualValue
     * @param \Generated\Shared\Transfer\CartPreCheckResponseTransfer $responseTransfer
     *
     * @return void
     */
    protected function addViolation(string $message, string $sku, float $restrictionValue, float $actualValue, CartPreCheckResponseTransfer $responseTransfer): void
    {
        $responseTransfer->setIsSuccess(false);
        $responseTransfer->addMessage(
            (new MessageTransfer())
                ->setValue($message)
                ->setParameters(['%sku%' => $sku, '%restrictionValue%' => $restrictionValue, '%actualValue%' => $actualValue])
        );
    }

    /**
     * @param array $productPackagingUnitAmountTransferMap
     * @param string[] $requiredSkus
     *
     * @return \Generated\Shared\Transfer\ProductPackagingUnitAmountTransfer[]
     */
    protected function replaceMissingSkus(array $productPackagingUnitAmountTransferMap, array $requiredSkus): array
    {
        $defaultProductPackagingAmountTransfer = $this->getDefaultProductPackagingAmountTransfer();

        foreach ($requiredSkus as $sku) {
            if (isset($productPackagingUnitAmountTransferMap[$sku])) {
                continue;
            }

            $productPackagingUnitAmountTransferMap[$sku] = $defaultProductPackagingAmountTransfer;
        }

        return $productPackagingUnitAmountTransferMap;
    }

    /**
     * @return \Generated\Shared\Transfer\ProductPackagingUnitAmountTransfer
     */
    protected function getDefaultProductPackagingAmountTransfer(): ProductPackagingUnitAmountTransfer
    {
        return (new ProductPackagingUnitAmountTransfer())->fromArray(static::PRODUCT_PACKAGING_UNIT_AMOUNT_DEFAULT_VALUES);
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer[] $itemTransfers
     *
     * @return \Generated\Shared\Transfer\ProductPackagingUnitAmountTransfer[]
     */
    protected function mapProductPackagingUnitAmountTransfersBySku(array $itemTransfers): array
    {
        $productPackagingUnitAmountTransferMap = [];

        foreach ($itemTransfers as $itemTransfer) {
            $productPackagingUnitTransfer = $this->productPackagingUnitReader->findProductPackagingUnitByProductSku($itemTransfer->getSku());
            if ($productPackagingUnitTransfer) {
                $productPackagingUnitAmountTransferMap[$itemTransfer->getSku()] = $productPackagingUnitTransfer->getProductPackagingUnitAmount();
            }
        }

        return $productPackagingUnitAmountTransferMap;
    }
}
