<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductImage\Communication\Plugin;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Product\Dependency\Plugin\ProductConcretePluginReadInterface;

/**
 * @method \Spryker\Zed\ProductImage\Business\ProductImageFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductImage\Communication\ProductImageCommunicationFactory getFactory()
 */
class ProductConcreteReadPlugin extends AbstractPlugin implements ProductConcretePluginReadInterface
{
    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function read(ProductConcreteTransfer $productConcreteTransfer)
    {
        return $this->getFacade()->expandProductConcreteWithImageSets($productConcreteTransfer);
    }
}
