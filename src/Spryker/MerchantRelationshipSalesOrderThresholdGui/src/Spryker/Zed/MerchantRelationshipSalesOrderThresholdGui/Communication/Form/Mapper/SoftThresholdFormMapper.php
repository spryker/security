<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\Mapper;

use Generated\Shared\Transfer\MerchantRelationshipSalesOrderThresholdTransfer;
use Generated\Shared\Transfer\SalesOrderThresholdTypeTransfer;
use Spryker\Shared\MerchantRelationshipSalesOrderThresholdGui\MerchantRelationshipSalesOrderThresholdGuiConfig;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\ThresholdType;

class SoftThresholdFormMapper extends AbstractThresholdFormMapper implements ThresholdFormMapperInterface
{
    /**
     * @param array $data
     * @param \Generated\Shared\Transfer\MerchantRelationshipSalesOrderThresholdTransfer $merchantRelationshipSalesOrderThresholdTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipSalesOrderThresholdTransfer
     */
    public function map(array $data, MerchantRelationshipSalesOrderThresholdTransfer $merchantRelationshipSalesOrderThresholdTransfer): MerchantRelationshipSalesOrderThresholdTransfer
    {
        $merchantRelationshipSalesOrderThresholdTransfer = $this->setStoreAndCurrencyToSalesOrderThresholdTransfer($data, $merchantRelationshipSalesOrderThresholdTransfer);
        $merchantRelationshipSalesOrderThresholdTransfer = $this->setLocalizedMessagesToSalesOrderThresholdTransfer(
            $data,
            $merchantRelationshipSalesOrderThresholdTransfer,
            ThresholdType::PREFIX_SOFT
        );

        $merchantRelationshipSalesOrderThresholdTransfer->getSalesOrderThresholdValue()->setThreshold($data[ThresholdType::FIELD_SOFT_THRESHOLD]);

        $salesOrderThresholdTypeTransfer = (new SalesOrderThresholdTypeTransfer())
            ->setKey(MerchantRelationshipSalesOrderThresholdGuiConfig::SOFT_TYPE_STRATEGY_MESSAGE)
            ->setThresholdGroup(MerchantRelationshipSalesOrderThresholdGuiConfig::GROUP_SOFT);
        $merchantRelationshipSalesOrderThresholdTransfer->getSalesOrderThresholdValue()->setSalesOrderThresholdType($salesOrderThresholdTypeTransfer);

        return $merchantRelationshipSalesOrderThresholdTransfer;
    }
}
