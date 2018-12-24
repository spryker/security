<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamationGui\Communication\Model;

use ArrayObject;

interface ReclamationItemEventsFinderInterface
{
    /**
     * @param \ArrayObject $reclamationItems
     * @param array $eventsGroupedByItem
     *
     * @return string[]
     */
    public function getDistinctManualEventsByReclamationItems(
        ArrayObject $reclamationItems,
        array $eventsGroupedByItem
    );
}
