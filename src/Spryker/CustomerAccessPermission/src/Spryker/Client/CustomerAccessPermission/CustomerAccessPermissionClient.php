<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\CustomerAccessPermission;

use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\CustomerAccessPermission\CustomerAccessPermissionFactory getFactory()
 */
class CustomerAccessPermissionClient extends AbstractClient implements CustomerAccessPermissionClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $customerSecuredPattern
     *
     * @return string
     */
    public function getCustomerSecuredPatternAccordingCustomerAccess(string $customerSecuredPattern): string
    {
        return $this->getFactory()->createCustomerAccess()->getCustomerSecuredPatternAccordingCustomerAccess($customerSecuredPattern);
    }
}
