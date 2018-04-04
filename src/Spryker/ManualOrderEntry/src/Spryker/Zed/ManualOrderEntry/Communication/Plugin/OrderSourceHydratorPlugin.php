<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntry\Communication\Plugin;

use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\SpySalesOrderEntityTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Sales\Dependency\Plugin\PreSaveOrderHydratePluginInterface;

/**
 * @method \Spryker\Zed\ManualOrderEntry\Business\ManualOrderEntryFacadeInterface getFacade()
 */
class OrderSourceHydratorPlugin extends AbstractPlugin implements PreSaveOrderHydratePluginInterface
{
    /**
     * Specification:
     *   - Its a plugin which hydrates SpySalesOrderEntityTransfer before order created
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\SpySalesOrderEntityTransfer $salesOrderEntityTransfer
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\SpySalesOrderEntityTransfer
     */
    public function hydrate(SpySalesOrderEntityTransfer $salesOrderEntityTransfer, QuoteTransfer $quoteTransfer): SpySalesOrderEntityTransfer
    {
        return $this->getFacade()->hydrateOrderSource($salesOrderEntityTransfer, $quoteTransfer);
    }
}
