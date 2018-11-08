<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CheckoutRestApi\Dependency\Facade;

use Generated\Shared\Transfer\CheckoutResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;

class CheckoutRestApiToCheckoutFacadeBridge implements CheckoutRestApiToCheckoutFacadeInterface
{
    /**
     * @var \Spryker\Zed\Checkout\Business\CheckoutFacadeInterface
     */
    protected $checkoutFacade;

    /**
     * @param \Spryker\Zed\Checkout\Business\CheckoutFacadeInterface $checkoutFacade
     */
    public function __construct($checkoutFacade)
    {
        $this->checkoutFacade = $checkoutFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\CheckoutResponseTransfer
     */
    public function placeOrder(QuoteTransfer $quoteTransfer): CheckoutResponseTransfer
    {
        return $this->checkoutFacade->placeOrder($quoteTransfer);
    }
}
