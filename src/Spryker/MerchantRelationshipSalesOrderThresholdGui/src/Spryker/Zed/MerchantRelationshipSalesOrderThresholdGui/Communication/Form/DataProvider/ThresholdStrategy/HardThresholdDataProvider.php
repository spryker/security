<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\DataProvider\ThresholdStrategy;

use Generated\Shared\Transfer\MerchantRelationshipSalesOrderThresholdTransfer;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\LocalizedForm;
use Spryker\Zed\MerchantRelationshipSalesOrderThresholdGui\Communication\Form\ThresholdType;

class HardThresholdDataProvider implements ThresholdStrategyDataProviderInterface
{
    /**
     * @param array $data
     * @param \Generated\Shared\Transfer\MerchantRelationshipSalesOrderThresholdTransfer $merchantRelationshipSalesOrderThresholdTransfer
     *
     * @return array
     */
    public function getData(array $data, MerchantRelationshipSalesOrderThresholdTransfer $merchantRelationshipSalesOrderThresholdTransfer): array
    {
        $data[ThresholdType::FIELD_HARD_THRESHOLD] = $merchantRelationshipSalesOrderThresholdTransfer->getSalesOrderThresholdValue()->getThreshold();

        foreach ($merchantRelationshipSalesOrderThresholdTransfer->getLocalizedMessages() as $localizedMessage) {
            $localizedFormName = ThresholdType::getLocalizedFormName(ThresholdType::PREFIX_HARD, $localizedMessage->getLocaleCode());
            $data[$localizedFormName][LocalizedForm::FIELD_MESSAGE] = $localizedMessage->getMessage();
        }

        return $data;
    }
}
