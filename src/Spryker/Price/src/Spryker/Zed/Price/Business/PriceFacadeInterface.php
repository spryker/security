<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Price\Business;

use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\QuoteTransfer;

interface PriceFacadeInterface
{
    /**
     * Specification:
     *  - Returns all available price modes
     *
     * @api
     *
     * @return string[]
     */
    public function getPriceModes();

    /**
     * Specification:
     *  - Returns default price mode as configured in store
     *
     * @api
     *
     * @return string
     */
    public function getDefaultPriceMode();

    /**
     * Specification:
     *  - Returns net price mode identifier
     *
     * @api
     *
     * @return string
     */
    public function getNetPriceModeIdentifier();

    /**
     * Specification:
     *  - Returns gross price mode identifier
     *
     * @api
     *
     * @return string
     */
    public function getGrossPriceModeIdentifier();

    /**
     * Specification:
     *  - Verifies if provided quote price mode is available.
     *  - Returns error message if price mode not valid.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\MessageTransfer
     */
    public function validatePriceModeInQuote(QuoteTransfer $quoteTransfer): MessageTransfer;
}
