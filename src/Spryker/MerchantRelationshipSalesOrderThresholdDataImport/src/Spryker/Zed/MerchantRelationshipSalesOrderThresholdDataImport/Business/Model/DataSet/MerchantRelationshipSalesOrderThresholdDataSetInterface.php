<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace Spryker\Zed\MerchantRelationshipSalesOrderThresholdDataImport\Business\Model\DataSet;

interface MerchantRelationshipSalesOrderThresholdDataSetInterface
{
    public const COLUMN_MERCHANT_RELATIONSHIP_KEY = 'merchant_relation_key';
    public const COLUMN_STORE = 'store';
    public const COLUMN_CURRENCY = 'currency';
    public const COLUMN_SALES_ORDER_THRESHOLD_TYPE_KEY = 'threshold_type_key';
    public const COLUMN_THRESHOLD = 'threshold';
    public const COLUMN_FEE = 'fee';
}
