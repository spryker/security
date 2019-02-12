<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CartsRestApi\Communication\Plugin\CartsRestApi\QuoteCreator;

use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\RestQuoteRequestTransfer;
use Spryker\Zed\CartsRestApiExtension\Dependency\Plugin\QuoteCreatorPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\CartsRestApi\Business\CartsRestApiFacadeInterface getFacade()
 * @method \Spryker\Zed\CartsRestApi\CartsRestApiConfig getConfig()
 */
class SingleQuoteCreatorPlugin extends AbstractPlugin implements QuoteCreatorPluginInterface
{
    /**
     * {@inheritdoc}
     * - Creates a single quote for customer.
     * - Creating of more than one quote is not allowed.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\RestQuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function createQuote(RestQuoteRequestTransfer $quoteRequestTransfer): QuoteResponseTransfer
    {
        return $this->getFacade()->createSingleQuote($quoteRequestTransfer);
    }
}
