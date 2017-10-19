<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Availability\Storage;

interface AvailabilityStorageInterface
{
    /**
     * @param int $idProductAbstract
     *
     * @throws \Spryker\Client\Availability\Exception\ProductAvailabilityNotFoundException
     *
     * @return \Generated\Shared\Transfer\StorageAvailabilityTransfer
     */
    public function getProductAvailability($idProductAbstract);

    /**
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\StorageAvailabilityTransfer|null
     */
    public function findProductAvailability($idProductAbstract);
}
