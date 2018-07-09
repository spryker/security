<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\PriceProductMerchantRelationshipStorage\MerchantRelationshipFinder;

class CompanyBusinessUnitFinder implements CompanyBusinessUnitFinderInterface
{
    /**
     * @var \Spryker\Client\PriceProductMerchantRelationshipStorage\Dependency\Client\PriceProductMerchantRelationshipStorageToCustomerClientInterface
     */
    protected $customerClient;

    /**
     * @param \Spryker\Client\PriceProductMerchantRelationshipStorage\Dependency\Client\PriceProductMerchantRelationshipStorageToCustomerClientInterface $customerClient
     */
    public function __construct($customerClient)
    {
        $this->customerClient = $customerClient;
    }

    /**
     * @return int|null
     */
    public function findCurrentCustomerCompanyBusinessUnitId(): ?int
    {
        $customerTransfer = $this->customerClient->getCustomer();
        if (!$customerTransfer) {
            return null;
        }

        $companyTransfer = $customerTransfer->getCompanyUserTransfer();
        if (!$companyTransfer) {
            return null;
        }

        $companyBusinessUnit = $companyTransfer->getCompanyBusinessUnit();
        if (!$companyBusinessUnit) {
            return null;
        }

        if ($companyBusinessUnit->getMerchantRelationships()->count() === 0) {
            return null;
        }

        return $companyBusinessUnit->getIdCompanyBusinessUnit();
    }
}
