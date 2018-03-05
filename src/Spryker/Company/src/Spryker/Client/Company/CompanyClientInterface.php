<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Company;

use Generated\Shared\Transfer\CompanyResponseTransfer;
use Generated\Shared\Transfer\CompanyTransfer;

interface CompanyClientInterface
{
    /**
     * Specification:
     * - Creates new company.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyTransfer $companyTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function createCompany(CompanyTransfer $companyTransfer): CompanyResponseTransfer;
}
