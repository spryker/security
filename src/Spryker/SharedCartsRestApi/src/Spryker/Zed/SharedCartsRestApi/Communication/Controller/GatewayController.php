<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SharedCartsRestApi\Communication\Controller;

use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\ShareDetailCollectionTransfer;
use Spryker\Zed\Kernel\Communication\Controller\AbstractGatewayController;

/**
 * @method \Spryker\Zed\SharedCartsRestApi\Business\SharedCartsRestApiFacade getFacade()
 */
class GatewayController extends AbstractGatewayController
{
    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\ShareDetailCollectionTransfer
     */
    public function getSharedCartsByCartUuidAction(QuoteTransfer $quoteTransfer): ShareDetailCollectionTransfer
    {
        $result = $this->getFacade()->getSharedCartsByCartUuid($quoteTransfer);
        return $result;
    }
}
