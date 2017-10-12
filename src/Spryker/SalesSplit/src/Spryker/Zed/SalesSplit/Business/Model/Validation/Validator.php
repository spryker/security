<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesSplit\Business\Model\Validation;

use Orm\Zed\Sales\Persistence\SpySalesOrderItem;

class Validator implements ValidatorInterface
{
    /**
     * @var array
     */
    private $messages = [];

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $salesOrderItem
     * @param int $quantityToSplit
     *
     * @return bool
     */
    public function isValid(SpySalesOrderItem $salesOrderItem, $quantityToSplit)
    {
        $this->isValidQuantity($salesOrderItem, $quantityToSplit);
        $this->isBundled($salesOrderItem);
        $this->isDiscounted($salesOrderItem);
        $this->isDiscountedOption($salesOrderItem);

        return $this->messages === [];
    }

    /**
     * @return array
     */
    public function getMessages()
    {
        return $this->messages;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $salesOrderItem
     * @param int $quantityToSplit
     *
     * @return bool
     */
    protected function isValidQuantity(SpySalesOrderItem $salesOrderItem, $quantityToSplit)
    {
        if ($quantityToSplit < 1 || $salesOrderItem->getQuantity() <= $quantityToSplit) {
            $this->messages[] = Messages::VALIDATE_QUANTITY_MESSAGE;

            return false;
        }

        return true;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $salesOrderItem
     *
     * @return bool
     */
    protected function isBundled(SpySalesOrderItem $salesOrderItem)
    {
        if ($salesOrderItem->getFkSalesOrderItemBundle() !== null) {
            $this->messages[] = Messages::VALIDATE_BUNDLE_MESSAGE;

            return true;
        }

        return false;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $salesOrderItem
     *
     * @return bool
     */
    protected function isDiscounted(SpySalesOrderItem $salesOrderItem)
    {
        if ($salesOrderItem->countDiscounts() > 0) {
            $this->messages[] = Messages::VALIDATE_DISCOUNTED_MESSAGE;

            return true;
        }

        return false;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $salesOrderItem
     *
     * @return bool
     */
    protected function isDiscountedOption(SpySalesOrderItem $salesOrderItem)
    {
        if ($salesOrderItem->countOptions() <= 0) {
            return false;
        }

        foreach ($salesOrderItem->getOptions() as $orderItemOption) {
            if ($orderItemOption->countDiscounts() > 0) {
                $this->messages[] = Messages::VALIDATE_DISCOUNTED_OPTION_MESSAGE;

                return true;
            }
        }

        return false;
    }
}
