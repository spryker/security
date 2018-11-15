<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyUser\Communication\Plugin\Customer;

use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Zed\Customer\Dependency\Plugin\CustomerTransferExpanderPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\CompanyUser\Business\CompanyUserFacadeInterface getFacade()
 * @method \Spryker\Zed\CompanyUser\CompanyUserConfig getConfig()
 */
class CustomerTransferCompanyUserExpanderPlugin extends AbstractPlugin implements CustomerTransferExpanderPluginInterface
{
    /**
     * {@inheritdoc}
     * - Does not set company user if multiple company user accounts were found.
     * - Does not set company user if it is already set.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    public function expandTransfer(CustomerTransfer $customerTransfer): CustomerTransfer
    {
        return $this->addCompanyUserTransfer($customerTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    protected function addCompanyUserTransfer(CustomerTransfer $customerTransfer): CustomerTransfer
    {
        if ($customerTransfer->getCompanyUserTransfer() !== null) {
            return $customerTransfer;
        }

        if ($this->getFacade()->countActiveCompanyUsersByIdCustomer($customerTransfer) > 1) {
            return $customerTransfer;
        }

        $companyUserTransfer = $this->getFacade()->findActiveCompanyUserByCustomerId($customerTransfer);
        $customerTransfer->setCompanyUserTransfer($companyUserTransfer);

        return $customerTransfer;
    }
}
