<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductPackagingUnitStorage\Dependency\Client;

interface PriceProductStorageToStoreClientInterface
{
    /**
     * @return \Generated\Shared\Transfer\StoreTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function getCurrentStore();
}
