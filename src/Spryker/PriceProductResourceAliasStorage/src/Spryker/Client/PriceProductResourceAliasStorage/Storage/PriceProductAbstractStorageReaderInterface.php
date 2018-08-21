<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\PriceProductResourceAliasStorage\Storage;

use Generated\Shared\Transfer\PriceProductStorageTransfer;

interface PriceProductAbstractStorageReaderInterface
{
    /**
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\PriceProductStorageTransfer|null
     */
    public function findPriceProductAbstractStorageTransfer(string $sku): ?PriceProductStorageTransfer;
}
