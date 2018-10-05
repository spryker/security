<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\ProductCategoryFilterStorage;

use Spryker\Zed\ProductCategoryFilterStorage\ProductCategoryFilterStorageConfig;

class ProductCategoryFilterStorageConfigMock extends ProductCategoryFilterStorageConfig
{
    /**
     * @return bool
     */
    public function isSendingToQueue(): bool
    {
        return false;
    }
}
