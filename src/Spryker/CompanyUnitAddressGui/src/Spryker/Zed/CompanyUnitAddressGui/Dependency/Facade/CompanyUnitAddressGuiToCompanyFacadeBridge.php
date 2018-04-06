<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyUnitAddressGui\Dependency\Facade;

use Generated\Shared\Transfer\CompanyCollectionTransfer;

class CompanyUnitAddressGuiToCompanyFacadeBridge implements CompanyUnitAddressGuiToCompanyFacadeInterface
{
    /**
     * @var \Spryker\Zed\Company\Business\CompanyFacadeInterface
     */
    protected $companyFacade;

    /**
     * @param \Spryker\Zed\Company\Business\CompanyFacadeInterface $companyFacade
     */
    public function __construct($companyFacade)
    {
        $this->companyFacade = $companyFacade;
    }

    /**
     * @return \Generated\Shared\Transfer\CompanyCollectionTransfer
     */
    public function getCompanies(): CompanyCollectionTransfer
    {
        return $this->companyFacade->getCompanies();
    }
}
