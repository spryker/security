<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CartsRestApi\Business\CartItem;

use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\RestCartItemRequestTransfer;

interface CartItemUpdaterInterface
{
    /**
     * @param \Generated\Shared\Transfer\RestCartItemRequestTransfer $restCartItemRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function changeItemQuantity(RestCartItemRequestTransfer $restCartItemRequestTransfer): QuoteResponseTransfer;
}
