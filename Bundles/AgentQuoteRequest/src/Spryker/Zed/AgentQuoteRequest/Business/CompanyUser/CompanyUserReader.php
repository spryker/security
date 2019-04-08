<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\AgentQuoteRequest\Business\CompanyUser;

use Generated\Shared\Transfer\CompanyUserCollectionTransfer;
use Generated\Shared\Transfer\CompanyUserCriteriaTransfer;
use Spryker\Zed\AgentQuoteRequest\Dependency\Facade\AgentQuoteRequestToCompanyUserInterface;

class CompanyUserReader implements CompanyUserReaderInterface
{
    /**
     * @var \Spryker\Zed\AgentQuoteRequest\Dependency\Facade\AgentQuoteRequestToCompanyUserInterface
     */
    protected $companyUserFacade;

    /**
     * @param \Spryker\Zed\AgentQuoteRequest\Dependency\Facade\AgentQuoteRequestToCompanyUserInterface $companyUserFacade
     */
    public function __construct(AgentQuoteRequestToCompanyUserInterface $companyUserFacade)
    {
        $this->companyUserFacade = $companyUserFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyUserCriteriaTransfer $companyUserCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserCollectionTransfer
     */
    public function getCompanyUserCollectionByQuery(CompanyUserCriteriaTransfer $companyUserCriteriaTransfer): CompanyUserCollectionTransfer
    {
        return $this->companyUserFacade->getCompanyUserCollectionByQuery($companyUserCriteriaTransfer);
    }
}
