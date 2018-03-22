<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Refund\Business\Model\RefundCalculator;

use Generated\Shared\Transfer\RefundTransfer;
use Spryker\Zed\Refund\Business\Model\RefundCalculator\ExpenseRefundCalculator;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Refund
 * @group Business
 * @group Model
 * @group RefundCalculator
 * @group ExpenseRefundCalculatorTest
 * Add your own group annotations below this line
 */
class ExpenseRefundCalculatorTest extends AbstractRefundCalculatorTest
{
    /**
     * @return void
     */
    public function testCalculateRefundForOrderWithoutAlreadyRefundedItemsShouldNotAddExpenses()
    {
        $refundCalculationPlugin = new ExpenseRefundCalculator();
        $orderTransfer = $this->getOrderTransferWithoutRefundedItems();
        $salesOrderItems = [
            $this->getSalesOrderItemOne(),
        ];

        $refundTransfer = new RefundTransfer();
        $refundTransfer->setAmount(0);
        $refundCalculationPlugin->calculateRefund($refundTransfer, $orderTransfer, $salesOrderItems);

        $this->assertSame(0, $refundTransfer->getAmount());
    }

    /**
     * @return void
     */
    public function testCalculateRefundShouldIncludeExpenseWhenLastItemOfOrderShouldBeRefunded()
    {
        $refundCalculationPlugin = new ExpenseRefundCalculator;
        $orderTransfer = $this->getOrderTransferWithRefundedItem();
        $salesOrderItems = [
            $this->getSalesOrderItemTwo(),
        ];

        $refundTransfer = new RefundTransfer();
        $refundTransfer->setAmount(0);
        $refundCalculationPlugin->calculateRefund($refundTransfer, $orderTransfer, $salesOrderItems);

        $this->assertSame(10, $refundTransfer->getAmount());
    }
}
