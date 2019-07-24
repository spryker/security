<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteRequest\Communication\Plugin\CompanyUserExtension;

use Generated\Shared\Transfer\CompanyUserTransfer;
use Generated\Shared\Transfer\QuoteRequestFilterTransfer;
use Spryker\Zed\CompanyUserExtension\Dependency\Plugin\CompanyUserPreDeletePluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\QuoteRequest\QuoteRequestConfig getConfig()
 * @method \Spryker\Zed\QuoteRequest\Business\QuoteRequestFacadeInterface getFacade()
 * @method \Spryker\Zed\QuoteRequest\Communication\QuoteRequestCommunicationFactory getFactory()
 */
class QuoteRequestCompanyUserPreDeletePlugin extends AbstractPlugin implements CompanyUserPreDeletePluginInterface
{
    /**
     * {@inheritDoc}
     * - Deletes all Quote Requests assigned to Company User.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return void
     */
    public function preDelete(CompanyUserTransfer $companyUserTransfer): void
    {
        $quoteRequestFilterTransfer = (new QuoteRequestFilterTransfer())->setIdCompanyUser(
            $companyUserTransfer->getIdCompanyUser()
        );

        $this->getFacade()->deleteQuoteRequestsForCompanyUser($quoteRequestFilterTransfer);
    }
}
