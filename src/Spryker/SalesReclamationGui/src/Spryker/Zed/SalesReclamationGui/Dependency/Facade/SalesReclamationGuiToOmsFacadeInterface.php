<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamationGui\Dependency\Facade;

interface SalesReclamationGuiToOmsFacadeInterface
{
    /**
     * @param int $idSalesOrder
     *
     * @return \Spryker\Zed\Oms\Business\Process\EventInterface[]
     */
    public function getManualEventsByIdSalesOrder($idSalesOrder);

    /**
     * @param int $idSalesOrder
     *
     * @return array
     */
    public function getDistinctManualEventsByIdSalesOrder($idSalesOrder);
}
