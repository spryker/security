<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesOrderThresholdGui\Communication\Form\Mapper;

use Generated\Shared\Transfer\SalesOrderThresholdTransfer;
use Generated\Shared\Transfer\SalesOrderThresholdTypeTransfer;
use Spryker\Shared\SalesOrderThresholdGui\SalesOrderThresholdGuiConfig;
use Spryker\Zed\SalesOrderThresholdGui\Communication\Form\GlobalThresholdType;

class GlobalSoftThresholdFlexibleFeeFormMapper extends AbstractGlobalThresholdFormMapper implements GlobalThresholdFormMapperInterface
{
    /**
     * @param array $data
     * @param \Generated\Shared\Transfer\SalesOrderThresholdTransfer $salesOrderThresholdTransfer
     *
     * @return \Generated\Shared\Transfer\SalesOrderThresholdTransfer
     */
    public function map(array $data, SalesOrderThresholdTransfer $salesOrderThresholdTransfer): SalesOrderThresholdTransfer
    {
        $salesOrderThresholdTransfer = $this->setStoreAndCurrencyToSalesOrderThresholdTransfer($data, $salesOrderThresholdTransfer);
        $salesOrderThresholdTransfer = $this->setLocalizedMessagesToSalesOrderThresholdTransfer(
            $data,
            $salesOrderThresholdTransfer,
            GlobalThresholdType::PREFIX_SOFT
        );

        $salesOrderThresholdTransfer->getSalesOrderThresholdValue()->setThreshold($data[GlobalThresholdType::FIELD_SOFT_THRESHOLD]);
        $salesOrderThresholdTransfer->getSalesOrderThresholdValue()->setFee($data[GlobalThresholdType::FIELD_SOFT_FLEXIBLE_FEE]);

        $salesOrderThresholdTypeTransfer = (new SalesOrderThresholdTypeTransfer())
            ->setKey(SalesOrderThresholdGuiConfig::SOFT_TYPE_STRATEGY_FLEXIBLE)
            ->setThresholdGroup(SalesOrderThresholdGuiConfig::GROUP_SOFT);
        $salesOrderThresholdTransfer->getSalesOrderThresholdValue()->setSalesOrderThresholdType($salesOrderThresholdTypeTransfer);

        return $salesOrderThresholdTransfer;
    }
}
