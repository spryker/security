<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Refund\Dependency\Facade;

interface RefundToSalesSplitInterface
{

    /**
     * @param int $idSalesOrderItem
     * @param int $quantity
     *
     *
     * @return \Generated\Shared\Transfer\ItemSplitResponseTransfer
     */
    public function splitSalesOrderItem($idSalesOrderItem, $quantity);

}