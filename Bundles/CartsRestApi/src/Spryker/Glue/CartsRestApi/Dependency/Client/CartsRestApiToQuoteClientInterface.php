<?php

/**
 * Copyright© 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CartsRestApi\Dependency\Client;

use Generated\Shared\Transfer\QuoteTransfer;

interface CartsRestApiToQuoteClientInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return void
     */
    public function setQuote(QuoteTransfer $quoteTransfer);

    /**
     * @return string
     */
    public function getStorageStrategy();

    /**
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function getQuote();
}
