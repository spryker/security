<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\PriceProductStorage\Storage;

use Generated\Shared\Transfer\CurrentProductPriceTransfer;
use Generated\Shared\Transfer\ItemTransfer;

interface PriceConcreteResolverInterface
{
    /**
     * @param int $idProductConcrete
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function resolvePriceProductConcrete(int $idProductConcrete, int $idProductAbstract): array;

    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return \Generated\Shared\Transfer\CurrentProductPriceTransfer
     */
    public function resolveCurrentProductPriceTransfer(ItemTransfer $itemTransfer): CurrentProductPriceTransfer;
}
