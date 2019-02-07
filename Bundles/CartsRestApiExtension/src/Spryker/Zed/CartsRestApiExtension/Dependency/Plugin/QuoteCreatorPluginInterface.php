<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CartsRestApiExtension\Dependency\Plugin;

use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\RestQuoteRequestTransfer;

interface QuoteCreatorPluginInterface
{
    /**
     * Specification:
     *  - This plugin method is used to create quote in CartsRestApi module.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\RestQuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function createQuote(RestQuoteRequestTransfer $quoteRequestTransfer): QuoteResponseTransfer;
}
