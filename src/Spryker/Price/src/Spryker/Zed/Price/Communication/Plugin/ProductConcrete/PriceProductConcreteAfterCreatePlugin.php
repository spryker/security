<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Price\Communication\Plugin\ProductConcrete;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Product\Dependency\Plugin\ProductConcretePluginCreateInterface;

/**
 * @method \Spryker\Zed\Price\Business\PriceFacade getFacade()
 * @method \Spryker\Zed\Price\Communication\PriceCommunicationFactory getFactory()
 */
class PriceProductConcreteAfterCreatePlugin extends AbstractPlugin implements ProductConcretePluginCreateInterface
{
    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function create(ProductConcreteTransfer $productConcreteTransfer)
    {
        return $this->getFacade()->persistProductConcretePriceCollection($productConcreteTransfer);
    }
}
