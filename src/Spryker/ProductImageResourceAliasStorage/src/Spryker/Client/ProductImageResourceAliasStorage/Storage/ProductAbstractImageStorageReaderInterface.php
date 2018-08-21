<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductImageResourceAliasStorage\Storage;

use Generated\Shared\Transfer\ProductAbstractImageStorageTransfer;

interface ProductAbstractImageStorageReaderInterface
{
    /**
     * @param string $sku
     * @param string $localeName
     *
     * @return \Generated\Shared\Transfer\ProductAbstractImageStorageTransfer|null
     */
    public function findProductAbstractImageStorageData(string $sku, string $localeName): ?ProductAbstractImageStorageTransfer;
}
