<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyBusinessUnit\Communication\Plugin;

use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Generated\Shared\Transfer\CompanyUserTransfer;
use Spryker\Zed\CompanyUser\Dependency\Plugin\CompanyUserHydrationPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\CompanyBusinessUnit\Persistence\CompanyBusinessUnitRepositoryInterface getRepository()
 * @method \Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitFacadeInterface getFacade()
 */
class CompanyBusinessUnitHydratePlugin extends AbstractPlugin implements CompanyUserHydrationPluginInterface
{
    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserTransfer
     */
    public function hydrate(CompanyUserTransfer $companyUserTransfer): CompanyUserTransfer
    {
        $businessUnitTransfer = new CompanyBusinessUnitTransfer();
        $businessUnitTransfer->setIdCompanyBusinessUnit($companyUserTransfer->getFkCompanyBusinessUnit());
        $businessUnitTransfer = $this->getFacade()->getCompanyBusinessUnitById($businessUnitTransfer);
        $companyUserTransfer->setCompanyBusinessUnit($businessUnitTransfer);

        return $companyUserTransfer;
    }
}
