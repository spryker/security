<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MultiCart\Communication\Plugin;

use Generated\Shared\Transfer\QuoteResponseTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\PersistentCart\Dependency\Plugin\QuoteResponseExpanderPluginInterface;

/**
 * @method \Spryker\Zed\MultiCart\Communication\MultiCartCommunicationFactory getFactory()
 * @method \Spryker\Zed\MultiCart\Business\MultiCartFacadeInterface getFacade()
 */
class CustomerCartQuoteResponseExpanderPlugin extends AbstractPlugin implements QuoteResponseExpanderPluginInterface
{
    /**
     * Specification:
     * - Adds customer quote collection to quote response transfer after cart operation handling
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteResponseTransfer $quoteResponseTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function expand(QuoteResponseTransfer $quoteResponseTransfer): QuoteResponseTransfer
    {
        if (!$quoteResponseTransfer->getQuoteTransfer()) {
            return $quoteResponseTransfer;
        }
        $quoteTransfer = $quoteResponseTransfer->getQuoteTransfer();
        $quoteTransfer->requireCustomer();
        $customerQuoteCollectionTransfer = $this->getFacade()->findCustomerQuotes($quoteTransfer->getCustomer());
        $quoteResponseTransfer->setCustomerQuotes($customerQuoteCollectionTransfer);

        return $quoteResponseTransfer;
    }
}
