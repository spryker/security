<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAlternativeStorage\Dependency\Facade;

interface ProductAlternativeStorageToEventBehaviorFacadeInterface
{
    /**
     * @param \Generated\Shared\Transfer\EventEntityTransfer[] $eventTransfers
     *
     * @return int[]
     */
    public function getEventTransferIds(array $eventTransfers);

    /**
     * @param \Generated\Shared\Transfer\EventEntityTransfer[] $eventTransfers
     * @param string $foreignKeyColumnName
     *
     * @return int[]
     */
    public function getEventTransferForeignKeys(array $eventTransfers, string $foreignKeyColumnName);
}
