<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\CompanyBusinessUnit\Helper;

use Codeception\Module;
use Generated\Shared\DataBuilder\CompanyBuilder;
use Generated\Shared\DataBuilder\CompanyBusinessUnitBuilder;
use Generated\Shared\DataBuilder\CompanyUserBuilder;
use Generated\Shared\DataBuilder\CustomerBuilder;
use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Generated\Shared\Transfer\CompanyTransfer;
use Generated\Shared\Transfer\CompanyUserTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Orm\Zed\CompanyBusinessUnit\Persistence\SpyCompanyBusinessUnitQuery;
use Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitFacadeInterface;
use SprykerTest\Shared\Testify\Helper\LocatorHelperTrait;

class CompanyBusinessUnitHelper extends Module
{
    use LocatorHelperTrait;

    /**
     * @param array $seedData
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitTransfer
     */
    public function haveCompanyBusinessUnit(array $seedData = []): CompanyBusinessUnitTransfer
    {
        if (!isset($seedData['fkCompany'])) {
            $seedData['fkCompany'] = $this->haveCompany()->getIdCompany();
        }

        $companyBusinessUnitTransfer = (new CompanyBusinessUnitBuilder($seedData))->build();
        $companyBusinessUnitTransfer->setIdCompanyBusinessUnit(null);

        return $this->getCompanyBusinessUnitFacade()
            ->create($companyBusinessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();
    }

    /**
     * @param string $key
     *
     * @return void
     */
    public function ensureCompanyBusinessUnitWithKeyDoesNotExist(string $key): void
    {
        $companyBusinessUnitQuery = $this->getCompanyBusinessUnitQuery();
        $companyBusinessUnitQuery->filterByKey($key)->delete();
    }

    /**
     * @param array $seedData
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitTransfer
     */
    public function haveCompanyBusinessUnitWithCompany(array $seedData = []): CompanyBusinessUnitTransfer
    {
        $company = $this->haveCompany();
        if (empty($seedData[CompanyBusinessUnitTransfer::FK_COMPANY])) {
            $seedData[CompanyBusinessUnitTransfer::FK_COMPANY] = $company->getIdCompany();
        }

        $companyBusinessUnitTransfer = (new CompanyBusinessUnitBuilder($seedData))->build();
        $companyBusinessUnitTransfer->setIdCompanyBusinessUnit(null);

        return $this->getCompanyBusinessUnitFacade()
            ->create($companyBusinessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();
    }

    /**
     * @param array $seedData
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    public function haveCustomer(array $seedData = []): CustomerTransfer
    {
        $companyTransfer = (new CustomerBuilder($seedData))->build();
        $customerFacade = $this->getLocator()->customer()->facade();

        $customerFacade->addCustomer($companyTransfer);

        return $customerFacade->getCustomer($companyTransfer);
    }

    /**
     * @param string $reference
     *
     * @return void
     */
    public function ensureCustomerWithReferenceDoesNotExist($reference): void
    {
        $customerFacade = $this->getLocator()->customer()->facade();
        $customerTransfer = $customerFacade->findByReference($reference);

        if ($customerTransfer) {
            $customerFacade->deleteCustomer($customerTransfer);
        }
    }

    /**
     * @param array $seedData
     *
     * @return \Generated\Shared\Transfer\CompanyUserTransfer
     */
    public function haveCompanyUser(array $seedData = []): CompanyUserTransfer
    {
        $companyUserTransfer = (new CompanyUserBuilder($seedData))->build();
        $companyUserFacade = $this->getLocator()->companyUser()->facade();

        $companyUserResponseTransfer = $companyUserFacade->create($companyUserTransfer);

        return $companyUserFacade->getCompanyUserById($companyUserResponseTransfer->getCompanyUser()->getIdCompanyUser());
    }

    /**
     * @return \Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitFacadeInterface
     */
    protected function getCompanyBusinessUnitFacade(): CompanyBusinessUnitFacadeInterface
    {
        return $this->getLocator()->companyBusinessUnit()->facade();
    }

    /**
     * @param array $seedData
     *
     * @return \Generated\Shared\Transfer\CompanyTransfer
     */
    protected function haveCompany(array $seedData = []): CompanyTransfer
    {
        $companyTransfer = (new CompanyBuilder($seedData))->build();

        return $this->getLocator()
            ->company()
            ->facade()
            ->create($companyTransfer)
            ->getCompanyTransfer();
    }

    /**
     * @return \Orm\Zed\CompanyBusinessUnit\Persistence\SpyCompanyBusinessUnitQuery
     */
    protected function getCompanyBusinessUnitQuery(): SpyCompanyBusinessUnitQuery
    {
        return SpyCompanyBusinessUnitQuery::create();
    }
}
