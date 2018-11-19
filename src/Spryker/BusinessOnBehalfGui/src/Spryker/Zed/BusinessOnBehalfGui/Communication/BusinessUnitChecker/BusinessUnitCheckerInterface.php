<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\BusinessOnBehalfGui\Communication\BusinessUnitChecker;

use Generated\Shared\Transfer\CompanyUserTransfer;

interface BusinessUnitCheckerInterface
{
    /**
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return bool
     */
    public function checkBusinessUnitOfCompanyUserExist(CompanyUserTransfer $companyUserTransfer): bool;
}
