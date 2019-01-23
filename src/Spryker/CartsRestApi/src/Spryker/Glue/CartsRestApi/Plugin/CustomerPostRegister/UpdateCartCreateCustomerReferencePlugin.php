<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CartsRestApi\Plugin\CustomerPostRegister;

use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Glue\CustomersRestApiExtension\Dependency\Plugin\CustomerPostCreatePluginInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\Kernel\AbstractPlugin;

/**
 * @method \Spryker\Glue\CartsRestApi\CartsRestApiFactory getFactory()
 */
class UpdateCartCreateCustomerReferencePlugin extends AbstractPlugin implements CustomerPostCreatePluginInterface
{
    /**
     * {@inheritdoc}
     *  - Updates cart of guest customer with customer reference after registration.
     *
     * @api
     *
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    public function postRegister(RestRequestInterface $restRequest, CustomerTransfer $customerTransfer): CustomerTransfer
    {
        return $this->getFactory()
            ->createGuestCartUpdater()
            ->updateGuestCartCustomerReferenceOnCreate($restRequest, $customerTransfer);
    }
}
