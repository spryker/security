<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\BusinessOnBehalf\Business\Model\CompanyUser;

use Generated\Shared\Transfer\CompanyUserCollectionTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Zed\BusinessOnBehalf\Dependency\Facade\BusinessOnBehalfToCompanyUserFacadeInterface;
use Spryker\Zed\BusinessOnBehalf\Persistence\BusinessOnBehalfRepositoryInterface;

class CompanyUserReader implements CompanyUserReaderInterface
{
    /**
     * @var \Spryker\Zed\BusinessOnBehalf\Persistence\BusinessOnBehalfRepositoryInterface
     */
    protected $repository;

    /**
     * @var \Spryker\Zed\BusinessOnBehalf\Dependency\Facade\BusinessOnBehalfToCompanyUserFacadeInterface
     */
    protected $companyUserFacade;

    /**
     * @param \Spryker\Zed\BusinessOnBehalf\Persistence\BusinessOnBehalfRepositoryInterface $repository
     * @param \Spryker\Zed\BusinessOnBehalf\Dependency\Facade\BusinessOnBehalfToCompanyUserFacadeInterface $companyUserFacade
     */
    public function __construct(BusinessOnBehalfRepositoryInterface $repository, BusinessOnBehalfToCompanyUserFacadeInterface $companyUserFacade)
    {
        $this->repository = $repository;
        $this->companyUserFacade = $companyUserFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyUserCollectionTransfer
     */
    public function findActiveCompanyUsersByCustomerId(CustomerTransfer $customerTransfer): CompanyUserCollectionTransfer
    {
        $customerTransfer->requireIdCustomer();

        $companyUserCollection = new CompanyUserCollectionTransfer();
        $idCompanyUsers = $this->repository->findActiveCompanyUserIdsByCustomerId($customerTransfer->getIdCustomer());
        foreach ($idCompanyUsers as $idCompanyUser) {
            $companyUserCollection->addCompanyUser(
                $this->companyUserFacade->getCompanyUserById($idCompanyUser)
            );
        }

        return $companyUserCollection;
    }
}
