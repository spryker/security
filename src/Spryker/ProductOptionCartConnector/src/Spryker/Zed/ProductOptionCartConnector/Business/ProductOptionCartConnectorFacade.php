<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOptionCartConnector\Business;

use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductOptionCartConnector\Business\ProductOptionCartConnectorBusinessFactory getFactory()
 */
class ProductOptionCartConnectorFacade extends AbstractFacade implements ProductOptionCartConnectorFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $changeTransfer
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function expandProductOptions(CartChangeTransfer $changeTransfer)
    {
        return $this->getFactory()
            ->createProductOptionValueExpander()
            ->expandProductOptions($changeTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $changeTransfer
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function expandGroupKey(CartChangeTransfer $changeTransfer)
    {
        return $this->getFactory()
            ->createGroupKeyExpander()
            ->expand($changeTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function changeProductOptionInCartQuantity(QuoteTransfer $quoteTransfer)
    {
        return $this->getFactory()
            ->createProductOptionCartQuantity()
            ->changeQuantity($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartPreCheckResponseTransfer
     */
    public function validateProductOptionValuePrices(CartChangeTransfer $cartChangeTransfer)
    {
        return $this->getFactory()
            ->createProductOptionValuePriceValidator()
            ->validateProductOptionValuePrices($cartChangeTransfer);
    }
}
