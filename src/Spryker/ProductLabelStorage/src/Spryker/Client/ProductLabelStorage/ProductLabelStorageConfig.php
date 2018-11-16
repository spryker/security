<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductLabelStorage;

use Spryker\Client\Kernel\AbstractBundleConfig;

class ProductLabelStorageConfig extends AbstractBundleConfig
{
    /**
     * To be able to work with data exported with collectors to redis, we need to bring this module into compatibility
     * mode. If this is turned on the ProductLabelClient will be used instead.
     *
     * @return bool
     */
    public static function isCollectorCompatibilityMode(): bool
    {
        return true;
    }
}
