<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\ProductPackagingUnit;

use ArrayObject;
use Codeception\Actor;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer;
use Generated\Shared\Transfer\QuoteTransfer;

/**
 * Inherited Methods
 * @method void wantToTest($text)
 * @method void wantTo($text)
 * @method void execute($callable)
 * @method void expectTo($prediction)
 * @method void expect($prediction)
 * @method void amGoingTo($argumentation)
 * @method void am($role)
 * @method void lookForwardTo($achieveValue)
 * @method void comment($description)
 * @method \Codeception\Lib\Friend haveFriend($name, $actorClass = null)
 *
 * @SuppressWarnings(PHPMD)
 */
class ProductPackagingUnitBusinessTester extends Actor
{
    use _generated\ProductPackagingUnitBusinessTesterActions;

    /**
     * @param int $amount
     * @param int $quantity
     * @param float $conversion
     * @param int $precision
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function createQuoteTransferForValueCalculation(int $amount, int $quantity, float $conversion, int $precision): QuoteTransfer
    {
        return (new QuoteTransfer())
            ->addItem((new ItemTransfer())
                ->setAmount($amount)
                ->setQuantity($quantity)
                ->setAmountSalesUnit(
                    (new ProductMeasurementSalesUnitTransfer())
                        ->setConversion($conversion)
                        ->setPrecision($precision)
                ));
    }

    /**
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function createEmptyCartChangeTransfer(): CartChangeTransfer
    {
        return (new CartChangeTransfer())
            ->setQuote(
                (new QuoteTransfer())
                    ->setItems(new ArrayObject([]))
            )
            ->setItems(new ArrayObject([]));
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $boxProductConcreteTransfer
     * @param \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer $productMeasurementSalesUnitTransfer
     * @param int $quoteAmount
     * @param int $quoteQuantity
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function createCartChangeTransferForProductPackagingUnitValidation(
        ProductConcreteTransfer $boxProductConcreteTransfer,
        ProductMeasurementSalesUnitTransfer $productMeasurementSalesUnitTransfer,
        int $quoteAmount,
        int $quoteQuantity
    ): CartChangeTransfer {
        $cartChangeTransfer = (new CartChangeTransfer())
            ->setQuote(
                (new QuoteTransfer())
                    ->addItem(
                        (new ItemTransfer())
                            ->setSku($boxProductConcreteTransfer->getSku())
                            ->setGroupKey(uniqid())
                            ->setQuantity($quoteQuantity)
                    )
            )
            ->addItem(
                (new ItemTransfer())
                    ->setSku($boxProductConcreteTransfer->getSku())
                    ->setQuantity($quoteQuantity)
                    ->setAmount($quoteAmount)
                    ->setAmountSalesUnit($productMeasurementSalesUnitTransfer)
                    ->setGroupKey(uniqid())
            );

        return $cartChangeTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     * @param string $sku
     * @param int $amount
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function addSkuToCartChangeTransfer(CartChangeTransfer $cartChangeTransfer, string $sku, int $amount): CartChangeTransfer
    {
        $cartChangeTransfer->addItem(
            (new ItemTransfer())
                ->setSku($sku)
                ->setAmount($amount)
        );

        return $cartChangeTransfer;
    }

    /**
     * @param string $dummyGroupKey
     * @param int $dummyAmount
     * @param int $dummyQuantity
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function createCartChangeTransferWithountAmountSalesUnitForGroupKeyGeneration(string $dummyGroupKey, int $dummyAmount, int $dummyQuantity): CartChangeTransfer
    {
        return (new CartChangeTransfer())
            ->addItem(
                (new ItemTransfer())
                    ->setAmountSalesUnit(null)
                    ->setAmount($dummyAmount)
                    ->setQuantity($dummyQuantity)
                    ->setGroupKey($dummyGroupKey)
            );
    }

    /**
     * @param string $dummyGroupKey
     * @param int $dummyAmount
     * @param int $dummyQuantity
     * @param int $dummySalesUnitId
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function createCartChangeTransferWithAmountSalesUnitForGroupKeyGeneration(string $dummyGroupKey, int $dummyAmount, int $dummyQuantity, int $dummySalesUnitId): CartChangeTransfer
    {
        return (new CartChangeTransfer())
            ->addItem(
                (new ItemTransfer())
                    ->setAmountSalesUnit((new ProductMeasurementSalesUnitTransfer())->setIdProductMeasurementSalesUnit($dummySalesUnitId))
                    ->setAmount($dummyAmount)
                    ->setQuantity($dummyQuantity)
                    ->setGroupKey($dummyGroupKey)
            );
    }
}
