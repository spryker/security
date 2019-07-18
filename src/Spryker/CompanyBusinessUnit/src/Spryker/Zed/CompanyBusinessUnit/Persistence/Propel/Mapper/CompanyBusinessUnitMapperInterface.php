<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyBusinessUnit\Persistence\Propel\Mapper;

use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Generated\Shared\Transfer\SpyCompanyBusinessUnitEntityTransfer;
use Orm\Zed\CompanyBusinessUnit\Persistence\SpyCompanyBusinessUnit;

interface CompanyBusinessUnitMapperInterface
{
    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $businessUnitTransfer
     * @param \Generated\Shared\Transfer\SpyCompanyBusinessUnitEntityTransfer $businessUnitEntityTransfer
     *
     * @return \Generated\Shared\Transfer\SpyCompanyBusinessUnitEntityTransfer
     */
    public function mapBusinessUnitTransferToEntityTransfer(
        CompanyBusinessUnitTransfer $businessUnitTransfer,
        SpyCompanyBusinessUnitEntityTransfer $businessUnitEntityTransfer
    ): SpyCompanyBusinessUnitEntityTransfer;

    /**
     * @param \Generated\Shared\Transfer\SpyCompanyBusinessUnitEntityTransfer $businessUnitEntityTransfer
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $businessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitTransfer
     */
    public function mapEntityTransferToBusinessUnitTransfer(
        SpyCompanyBusinessUnitEntityTransfer $businessUnitEntityTransfer,
        CompanyBusinessUnitTransfer $businessUnitTransfer
    ): CompanyBusinessUnitTransfer;

    /**
     * @param \Orm\Zed\CompanyBusinessUnit\Persistence\SpyCompanyBusinessUnit $companyBusinessUnitEntity
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitTransfer
     */
    public function mapCompanyBusinessUnitEntityToCompanyBusinessUnitTransfer(
        SpyCompanyBusinessUnit $companyBusinessUnitEntity,
        CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
    ): CompanyBusinessUnitTransfer;
}
