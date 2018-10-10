<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductPackagingUnitStorage\Plugin\QuickOrder;

use Generated\Shared\Transfer\ItemTransfer;
use Spryker\Client\Kernel\AbstractPlugin;
use Spryker\Client\QuickOrderExtension\Dependency\Plugin\QuickOrderItemTransferExpanderPluginInterface;

/**
 * @method \Spryker\Client\ProductPackagingUnitStorage\ProductPackagingUnitStorageClientInterface getClient()
 * @method \Spryker\Client\ProductPackagingUnitStorage\ProductPackagingUnitStorageFactory getFactory()
 */
class QuickOrderItemTransferPackagingUnitExpanderPlugin extends AbstractPlugin implements QuickOrderItemTransferExpanderPluginInterface
{
    /**
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return \Generated\Shared\Transfer\ItemTransfer
     */
    public function expandItemTransfer(ItemTransfer $itemTransfer): ItemTransfer
    {
        return $this->getClient()->expandItemTransferWithPackagingUnit($itemTransfer);
    }
}
