<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\CompanyBusinessUnit\Zed;

use Generated\Shared\Transfer\CompanyBusinessUnitCollectionTransfer;
use Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer;
use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Spryker\Client\CompanyBusinessUnit\Dependency\Client\CompanyBusinessUnitToZedRequestClientInterface;

class CompanyBusinessUnitStub implements CompanyBusinessUnitStubInterface
{
    /**
     * @var \Spryker\Client\CompanyBusinessUnit\Dependency\Client\CompanyBusinessUnitToZedRequestClientInterface
     */
    protected $zedRequestClient;

    /**
     * @param \Spryker\Client\CompanyBusinessUnit\Dependency\Client\CompanyBusinessUnitToZedRequestClientInterface $zedRequestClient
     */
    public function __construct(CompanyBusinessUnitToZedRequestClientInterface $zedRequestClient)
    {
        $this->zedRequestClient = $zedRequestClient;
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function getCompanyBusinessUnitById(
        CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
    ): CompanyBusinessUnitResponseTransfer {
        return $this->zedRequestClient->call('/company-business-unit/gateway/get-company-business-unit-by-id', $companyBusinessUnitTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function createCompanyBusinessUnit(
        CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
    ): CompanyBusinessUnitResponseTransfer {
        return $this->zedRequestClient->call('/company-business-unit/gateway/create', $companyBusinessUnitTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function updateCompanyBusinessUnit(
        CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
    ): CompanyBusinessUnitResponseTransfer {
        return $this->zedRequestClient->call('/company-business-unit/gateway/update', $companyBusinessUnitTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return bool
     */
    public function deleteCompanyBusinessUnit(
        CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
    ): bool {
        /** @var \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer $companyBusinessUnitResponseTransfer */
        $companyBusinessUnitResponseTransfer = $this->zedRequestClient->call('/company-business-unit/gateway/delete', $companyBusinessUnitTransfer);

        return $companyBusinessUnitResponseTransfer->getIsSuccessful();
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitCollectionTransfer $businessUnitCollectionTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitCollectionTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function getCompanyBusinessUnitCollection(
        CompanyBusinessUnitCollectionTransfer $businessUnitCollectionTransfer
    ): CompanyBusinessUnitCollectionTransfer {
        return $this->zedRequestClient->call('/company-business-unit/gateway/get-company-business-unit-collection', $businessUnitCollectionTransfer);
    }
}
