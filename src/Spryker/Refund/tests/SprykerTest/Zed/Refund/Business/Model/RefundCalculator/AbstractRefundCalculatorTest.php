<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Refund\Business\Model\RefundCalculator;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\ExpenseTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\OrderTransfer;
use Orm\Zed\Sales\Persistence\SpySalesOrderItem;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Refund
 * @group Business
 * @group Model
 * @group RefundCalculator
 * @group AbstractRefundCalculatorTest
 * Add your own group annotations below this line
 */
class AbstractRefundCalculatorTest extends Unit
{
    /**
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    protected function getOrderTransferWithoutRefundedItems()
    {
        $orderTransfer = new OrderTransfer();

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setRefundableAmount(100);
        $itemTransfer->setIdSalesOrderItem(1);
        $orderTransfer->addItem($itemTransfer);

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setRefundableAmount(100);
        $itemTransfer->setIdSalesOrderItem(2);
        $orderTransfer->addItem($itemTransfer);

        $expenseTransfer = new ExpenseTransfer();
        $expenseTransfer->setRefundableAmount(10);
        $orderTransfer->addExpense($expenseTransfer);

        return $orderTransfer;
    }

    /**
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    protected function getOrderTransferWithRefundedItem()
    {
        $orderTransfer = new OrderTransfer();

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setRefundableAmount(0);
        $itemTransfer->setIdSalesOrderItem(1);
        $orderTransfer->addItem($itemTransfer);

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setRefundableAmount(100);
        $itemTransfer->setIdSalesOrderItem(2);
        $orderTransfer->addItem($itemTransfer);

        $expenseTransfer = new ExpenseTransfer();
        $expenseTransfer->setRefundableAmount(10);
        $orderTransfer->addExpense($expenseTransfer);

        return $orderTransfer;
    }

    /**
     * @return \Orm\Zed\Sales\Persistence\SpySalesOrderItem
     */
    protected function getSalesOrderItemOne()
    {
        $salesOrderItem = new SpySalesOrderItem();
        $salesOrderItem->setIdSalesOrderItem(1);

        return $salesOrderItem;
    }

    /**
     * @return \Orm\Zed\Sales\Persistence\SpySalesOrderItem
     */
    protected function getSalesOrderItemTwo()
    {
        $salesOrderItem = new SpySalesOrderItem();
        $salesOrderItem->setIdSalesOrderItem(2);

        return $salesOrderItem;
    }
}
