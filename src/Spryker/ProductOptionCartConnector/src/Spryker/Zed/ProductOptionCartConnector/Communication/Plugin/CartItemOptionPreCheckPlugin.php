<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOptionCartConnector\Communication\Plugin;

use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\CartPreCheckResponseTransfer;
use Spryker\Zed\Cart\Dependency\CartPreCheckPluginInterface;
use Spryker\Zed\Cart\Dependency\TerminationAwareCartPreCheckPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\ProductOptionCartConnector\Business\ProductOptionCartConnectorFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductOptionCartConnector\Communication\ProductOptionCartConnectorCommunicationFactory getFactory()
 */
class CartItemOptionPreCheckPlugin extends AbstractPlugin implements CartPreCheckPluginInterface, TerminationAwareCartPreCheckPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function check(CartChangeTransfer $cartChangeTransfer): CartPreCheckResponseTransfer
    {
        return $this->getFacade()->checkProductOptionExistence($cartChangeTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return bool
     */
    public function terminateOnFailure()
    {
        return true;
    }
}
