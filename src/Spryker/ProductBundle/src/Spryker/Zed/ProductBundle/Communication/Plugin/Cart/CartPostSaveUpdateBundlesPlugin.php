<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductBundle\Communication\Plugin\Cart;

use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\Cart\Dependency\PostSavePluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\ProductBundle\Business\ProductBundleFacade getFacade()
 * @method \Spryker\Zed\ProductBundle\Communication\ProductBundleCommunicationFactory getFactory()
 */
class CartPostSaveUpdateBundlesPlugin extends AbstractPlugin implements PostSavePluginInterface
{
    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     */
    public function postSave(QuoteTransfer $quoteTransfer)
    {
        return $this->getFacade()->postSaveCartUpdateBundles($quoteTransfer);
    }
}
