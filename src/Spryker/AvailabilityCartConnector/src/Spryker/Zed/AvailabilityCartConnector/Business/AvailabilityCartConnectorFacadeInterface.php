<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\AvailabilityCartConnector\Business;

use Generated\Shared\Transfer\CartChangeTransfer;

/**
 * @method \Spryker\Zed\AvailabilityCartConnector\Business\AvailabilityCartConnectorBusinessFactory getFactory()
 */
interface AvailabilityCartConnectorFacadeInterface
{
    /**
     * Specification:
     *  - Checks if newly added items have correct availability
     *  - Returns transfer with error message and isSuccess flag set to false when some of items are not available.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function checkCartAvailability(CartChangeTransfer $cartChangeTransfer);
}
