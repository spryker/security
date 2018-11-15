<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CheckoutRestApi\Business;

use Generated\Shared\Transfer\CheckoutDataResponseTransfer;
use Generated\Shared\Transfer\CheckoutResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;

interface CheckoutRestApiFacadeInterface
{
    /**
     * Specification:
     * - Provides checkout data based on data passed in QuoteTransfer.
     * - Checkout data will include available shipping methods, available payment methods and available customer addresses.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\CheckoutDataResponseTransfer
     */
    public function getCheckoutData(QuoteTransfer $quoteTransfer): CheckoutDataResponseTransfer;

    /**
     * Specification:
     * - Extends the Customer transfer with the customer data (for registered users).
     * - Updated billing and shipping addresses with full details if UUID is passed.
     * - Validates quote.
     * - Places an order.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\CheckoutResponseTransfer
     */
    public function placeOrder(QuoteTransfer $quoteTransfer): CheckoutResponseTransfer;
}
