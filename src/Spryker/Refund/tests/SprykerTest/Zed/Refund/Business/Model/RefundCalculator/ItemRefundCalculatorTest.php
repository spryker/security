<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Refund\Business\Model\RefundCalculator;

use Generated\Shared\Transfer\RefundTransfer;
use Spryker\Zed\Refund\Business\Model\RefundCalculator\ItemRefundCalculator;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Refund
 * @group Business
 * @group Model
 * @group RefundCalculator
 * @group ItemRefundCalculatorTest
 * Add your own group annotations below this line
 */
class ItemRefundCalculatorTest extends AbstractRefundCalculatorTest
{
    /**
     * @return void
     */
    public function testCalculateRefundForOrderWithoutAlreadyRefundedItems()
    {
        $refundCalculationPlugin = new ItemRefundCalculator();
        $orderTransfer = $this->getOrderTransferWithoutRefundedItems();
        $salesOrderItems = [
            $this->getSalesOrderItemOne(),
        ];

        $refundTransfer = new RefundTransfer();
        $refundTransfer->setAmount(0);
        $refundCalculationPlugin->calculateRefund($refundTransfer, $orderTransfer, $salesOrderItems);

        $this->assertSame(100, $refundTransfer->getAmount());
    }
}
