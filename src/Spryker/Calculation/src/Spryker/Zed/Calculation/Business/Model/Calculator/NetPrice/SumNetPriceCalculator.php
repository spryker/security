<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Calculation\Business\Model\Calculator\NetPrice;

use ArrayObject;
use Generated\Shared\Transfer\CalculableObjectTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\ProductOptionTransfer;
use Spryker\Zed\Calculation\Business\Model\Calculator\CalculatorInterface;

class SumNetPriceCalculator implements CalculatorInterface
{
    /**
     * @param \Generated\Shared\Transfer\CalculableObjectTransfer $calculableObjectTransfer
     *
     * @return void
     */
    public function recalculate(CalculableObjectTransfer $calculableObjectTransfer)
    {
        $this->calculateItemGrossAmountForItems($calculableObjectTransfer->getItems());
        $this->calculateSumGrossPriceForExpenses($calculableObjectTransfer->getExpenses());
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ExpenseTransfer[] $expenses
     *
     * @return void
     */
    protected function calculateSumGrossPriceForExpenses(ArrayObject $expenses)
    {
        foreach ($expenses as $expenseTransfer) {
            // BC: When ExpenseTransfer is populated from Persistence, sum price is accurate and populated, unit price is derived
            if ($expenseTransfer->getSumNetPrice()) {
                continue;
            }

            $expenseTransfer->setSumNetPrice($expenseTransfer->getUnitNetPrice() * $expenseTransfer->getQuantity());
        }
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function addCalculatedItemNetAmounts(ItemTransfer $itemTransfer)
    {
        $this->assertItemRequirements($itemTransfer);

        // BC: When ItemTransfer is populated from Persistence, sum price is accurate and populated, unit price is derived
        if ($itemTransfer->getSumNetPrice()) {
            return;
        }

        $itemTransfer->setSumNetPrice($itemTransfer->getUnitNetPrice() * $itemTransfer->getQuantity());
    }

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function assertItemRequirements(ItemTransfer $itemTransfer)
    {
        $itemTransfer->requireQuantity();
    }

    /**
     * @param \Generated\Shared\Transfer\ProductOptionTransfer $productOptionTransfer
     *
     * @return void
     */
    protected function assertProductOptionPriceCalculationRequirements(ProductOptionTransfer $productOptionTransfer)
    {
        $productOptionTransfer->requireQuantity();
    }

    /**
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $items
     *
     * @return void
     */
    protected function calculateItemGrossAmountForItems(ArrayObject $items)
    {
        foreach ($items as $itemTransfer) {
            $this->addCalculatedItemNetAmounts($itemTransfer);
            foreach ($itemTransfer->getProductOptions() as $productOptionTransfer) {
                $this->assertProductOptionPriceCalculationRequirements($productOptionTransfer);

                // BC: When ProductOptionTransfer is populated from Persistence, sum price is accurate and populated, unit price is derived
                if ($productOptionTransfer->getSumNetPrice()) {
                    continue;
                }

                $productOptionTransfer->setSumNetPrice($productOptionTransfer->getUnitNetPrice() * $productOptionTransfer->getQuantity());
            }
        }
    }
}
