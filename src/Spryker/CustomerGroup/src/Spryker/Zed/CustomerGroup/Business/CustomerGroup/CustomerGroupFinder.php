<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerGroup\Business\CustomerGroup;

use Generated\Shared\Transfer\CustomerGroupCollectionTransfer;
use Spryker\Zed\CustomerGroup\Persistence\CustomerGroupRepositoryInterface;

class CustomerGroupFinder implements CustomerGroupFinderInterface
{
    /**
     * @var \Spryker\Zed\CustomerGroup\Persistence\CustomerGroupRepositoryInterface
     */
    protected $customerGroupRepository;

    /**
     * @param \Spryker\Zed\CustomerGroup\Persistence\CustomerGroupRepositoryInterface $customerGroupRepository
     */
    public function __construct(CustomerGroupRepositoryInterface $customerGroupRepository)
    {
        $this->customerGroupRepository = $customerGroupRepository;
    }

    /**
     * @param int $idCustomer
     *
     * @return \Generated\Shared\Transfer\CustomerGroupCollectionTransfer
     */
    public function getCustomerGroupCollectionByIdCustomer(int $idCustomer): CustomerGroupCollectionTransfer
    {
        return $this->customerGroupRepository->getCustomerGroupCollectionByIdCustomer($idCustomer);
    }
}
