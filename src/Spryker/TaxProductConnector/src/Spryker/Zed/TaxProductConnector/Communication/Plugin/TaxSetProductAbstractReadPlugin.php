<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\TaxProductConnector\Communication\Plugin;

use Generated\Shared\Transfer\ProductAbstractTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Product\Dependency\Plugin\ProductAbstractPluginReadInterface;

/**
 * @method \Spryker\Zed\TaxProductConnector\Business\TaxProductConnectorFacadeInterface getFacade()
 */
class TaxSetProductAbstractReadPlugin extends AbstractPlugin implements ProductAbstractPluginReadInterface
{
    /**
     * @param \Generated\Shared\Transfer\ProductAbstractTransfer $productAbstractTransfer
     *
     * @return \Generated\Shared\Transfer\ProductAbstractTransfer
     */
    public function read(ProductAbstractTransfer $productAbstractTransfer)
    {
         return $this->getFacade()
             ->mapTaxSet($productAbstractTransfer);
    }
}
