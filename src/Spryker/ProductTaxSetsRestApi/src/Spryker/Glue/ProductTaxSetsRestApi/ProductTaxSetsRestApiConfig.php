<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductTaxSetsRestApi;

use Spryker\Glue\Kernel\AbstractBundleConfig;

class ProductTaxSetsRestApiConfig extends AbstractBundleConfig
{
    public const RESOURCE_TAX_SETS = 'product-tax-sets';

    public const RESPONSE_CODE_CANT_FIND_PRODUCT_TAX_SETS = '310';
    public const RESPONSE_DETAIL_CANT_FIND_PRODUCT_TAX_SETS = 'Product tax sets not found.';
}
