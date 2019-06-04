<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\QuoteRequest\Status;

use Generated\Shared\Transfer\QuoteRequestTransfer;

interface QuoteRequestStatusInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return bool
     */
    public function isQuoteRequestCancelable(QuoteRequestTransfer $quoteRequestTransfer): bool;

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return bool
     */
    public function isQuoteRequestReady(QuoteRequestTransfer $quoteRequestTransfer): bool;

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return bool
     */
    public function isQuoteRequestEditable(QuoteRequestTransfer $quoteRequestTransfer): bool;
}
