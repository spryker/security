<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProduct\Business\Model\Product;

use Generated\Shared\Transfer\PriceProductTransfer;

interface PriceProductStoreWriterInterface
{
    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $priceProductTransfer
     *
     * @return \Orm\Zed\PriceProduct\Persistence\SpyPriceProductStore
     */
    public function persistPriceProductStore(PriceProductTransfer $priceProductTransfer);
}
