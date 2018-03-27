<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MultiCart\Communication\Plugin;

use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\QuoteExtension\Dependency\Plugin\QuoteWritePluginInterface;

/**
 * @method \Spryker\Zed\MultiCart\MultiCartConfig getConfig()
 * @method \Spryker\Zed\MultiCart\Business\MultiCartFacadeInterface getFacade()
 * @method \Spryker\Zed\MultiCart\Communication\MultiCartCommunicationFactory getFactory()
 * @method \Spryker\Zed\MultiCart\Persistence\MultiCartRepositoryInterface getRepository()
 */
class ResolveQuoteNameBeforeQuoteCreatePlugin extends AbstractPlugin implements QuoteWritePluginInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function execute(QuoteTransfer $quoteTransfer): QuoteTransfer
    {
        if ($quoteTransfer->getName()) {
            $quoteByNameTransfer = $this->getRepository()
                ->findCustomerQuoteByName($quoteTransfer->getName(), $quoteTransfer->getCustomer()->getCustomerReference());
            if ($quoteByNameTransfer) {
                preg_match_all('/^.+ (\d+)$/', $quoteByNameTransfer->getName(), $matches, PREG_SET_ORDER);
                $lastQuoteSuffix = 1;
                if ($matches) {
                    $lastQuoteSuffix += (int)$matches[0][1];
                }
                $quoteTransfer->setName($quoteTransfer->getName() . ' ' . $lastQuoteSuffix);
            }
        }

        return $quoteTransfer;
    }
}
