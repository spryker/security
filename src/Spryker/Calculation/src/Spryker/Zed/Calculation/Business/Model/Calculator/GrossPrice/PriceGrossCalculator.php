<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Calculation\Business\Model\Calculator\GrossPrice;

use ArrayObject;
use Generated\Shared\Transfer\CalculableObjectTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Spryker\Zed\Calculation\Business\Model\Calculator\CalculatorInterface;

class PriceGrossCalculator implements CalculatorInterface
{
    /**
     * @param \Generated\Shared\Transfer\CalculableObjectTransfer $calculableObjectTransfer
     *
     * @return void
     */
    public function recalculate(CalculableObjectTransfer $calculableObjectTransfer)
    {
        $this->calculatePriceForItems($calculableObjectTransfer->getItems());
        $this->calculatePricesForExpenses($calculableObjectTransfer->getExpenses());
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $items
     *
     * @return void
     */
    protected function calculatePriceForItems(ArrayObject $items)
    {
        foreach ($items as $itemTransfer) {
            $itemTransfer->setUnitPrice($itemTransfer->getUnitGrossPrice());
            $itemTransfer->setSumPrice($itemTransfer->getSumGrossPrice());

            $this->recalculateProductOptionPrices($itemTransfer);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function recalculateProductOptionPrices(ItemTransfer $itemTransfer)
    {
        foreach ($itemTransfer->getProductOptions() as $productOptionTransfer) {
            $productOptionTransfer->setUnitPrice($productOptionTransfer->getUnitGrossPrice());
            $productOptionTransfer->setSumPrice($productOptionTransfer->getSumGrossPrice());
        }
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ExpenseTransfer[] $expenses
     *
     * @return void
     */
    protected function calculatePricesForExpenses(ArrayObject $expenses)
    {
        foreach ($expenses as $expenseTransfer) {
            $expenseTransfer->setUnitPrice($expenseTransfer->getUnitGrossPrice());
            $expenseTransfer->setSumPrice($expenseTransfer->getSumGrossPrice());
        }
    }
}
