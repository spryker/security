<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Customer\Plugin;

use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Client\Customer\Dependency\Plugin\CustomerSessionGetPluginInterface;
use Spryker\Client\Kernel\AbstractPlugin;

/**
 * @method \Spryker\Client\Customer\CustomerClientInterface getClient()
 */
class CustomerTransferRefreshPlugin extends AbstractPlugin implements CustomerSessionGetPluginInterface
{
    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return void
     */
    public function execute(CustomerTransfer $customerTransfer)
    {
        if ($customerTransfer && $customerTransfer->getIsDirty()) {
            $customerTransfer = $this->getClient()->getCustomerById($customerTransfer->getIdCustomer());
            $this->getClient()->setCustomer($customerTransfer);
        }
    }
}
