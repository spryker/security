<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyRole\Persistence\Mapper;

use Generated\Shared\Transfer\CompanyRoleTransfer;
use Generated\Shared\Transfer\CompanyUserCollectionTransfer;
use Generated\Shared\Transfer\CompanyUserTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Orm\Zed\CompanyRole\Persistence\SpyCompanyRole;

class CompanyRoleCompanyUserMapper implements CompanyRoleCompanyUserMapperInterface
{
    /**
     * @param \Orm\Zed\CompanyRole\Persistence\SpyCompanyRole $spyCompanyRole
     * @param \Generated\Shared\Transfer\CompanyRoleTransfer $companyRoleTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyRoleTransfer
     */
    public function hydrateCompanyUserCollection(
        SpyCompanyRole $spyCompanyRole,
        CompanyRoleTransfer $companyRoleTransfer
    ): CompanyRoleTransfer {
        $companyUserCollectionTransfer = new CompanyUserCollectionTransfer();

        foreach ($spyCompanyRole->getSpyCompanyRoleToCompanyUsersJoinCompanyUser() as $spyCompanyRoleToCompanyUser) {
            /** @var \Orm\Zed\Customer\Persistence\SpyCustomer|null $customerEntity */
            $customerEntity = $spyCompanyRoleToCompanyUser->getCompanyUser()->getCustomer();

            if ($customerEntity === null) {
                continue;
            }

            $companyUserTransfer = (new CompanyUserTransfer())
                ->fromArray($spyCompanyRoleToCompanyUser->getCompanyUser()->toArray(), true);

            $customerTransfer = new CustomerTransfer();
            $customerTransfer->fromArray($customerEntity->toArray(), true);

            $companyUserTransfer->setCustomer($customerTransfer);

            $companyUserCollectionTransfer->addCompanyUser($companyUserTransfer);
        }

        $companyRoleTransfer->setCompanyUserCollection($companyUserCollectionTransfer);

        return $companyRoleTransfer;
    }
}
