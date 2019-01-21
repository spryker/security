<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteRequest\Business\QuoteRequest;

use Generated\Shared\Transfer\QuoteRequestTransfer;
use Generated\Shared\Transfer\QuoteRequestVersionTransfer;

interface QuoteRequestReferenceGeneratorInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return string
     */
    public function generateQuoteRequestReference(QuoteRequestTransfer $quoteRequestTransfer);

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     * @param \Generated\Shared\Transfer\QuoteRequestVersionTransfer $quoteRequestVersionTransfer
     *
     * @return string
     */
    public function generateQuoteRequestVersionReference(
        QuoteRequestTransfer $quoteRequestTransfer,
        QuoteRequestVersionTransfer $quoteRequestVersionTransfer
    ): string;
}
