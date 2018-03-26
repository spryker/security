<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductCategoryFilterStorage\Dependency\Client;

interface ProductCategoryFilterStorageToStorageInterface
{
    /**
     * @param string $key
     *
     * @return array
     */
    public function get($key);
}
