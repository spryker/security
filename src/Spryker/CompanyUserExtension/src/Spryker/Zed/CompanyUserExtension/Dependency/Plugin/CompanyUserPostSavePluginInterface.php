<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyUserExtension\Dependency\Plugin;

use Generated\Shared\Transfer\CompanyUserTransfer;

interface CompanyUserPostSavePluginInterface
{
    /**
     * Specification:
     * - Executes plugins after a company user is saved
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserTransfer
     */
    public function postSave(CompanyUserTransfer $companyUserTransfer): CompanyUserTransfer;
}
