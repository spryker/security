<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductLabelStorage;

use Spryker\Zed\Kernel\AbstractBundleConfig;

class ProductLabelStorageConfig extends AbstractBundleConfig
{
    /**
     * @return bool
     */
    public function isSendingToQueue(): bool
    {
        return true;
    }

    /**
     * @return string|null
     */
    public function getProductAbstractLabelSynchronizationPoolName(): ?string
    {
        return null;
    }

    /**
     * @return string|null
     */
    public function getProductLabelDictionarySynchronizationPoolName(): ?string
    {
        return null;
    }
}
