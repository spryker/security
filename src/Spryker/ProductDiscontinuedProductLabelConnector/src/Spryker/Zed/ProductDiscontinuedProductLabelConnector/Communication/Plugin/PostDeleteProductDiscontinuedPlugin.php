<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedProductLabelConnector\Communication\Plugin;

use Generated\Shared\Transfer\ProductDiscontinuedTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductDiscontinuedExtension\Dependency\Plugin\PostDeleteProductDiscontinuedPluginInterface;

/**
 * @method \Spryker\Zed\ProductDiscontinuedProductLabelConnector\Business\ProductDiscontinuedProductLabelConnectorFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductDiscontinuedProductLabelConnector\ProductDiscontinuedProductLabelConnectorConfig getConfig()
 */
class PostDeleteProductDiscontinuedPlugin extends AbstractPlugin implements PostDeleteProductDiscontinuedPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * Specification:
     *  - Removes "Discontinued" label if applicable.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductDiscontinuedTransfer $productDiscontinuedTransfer
     *
     * @return void
     */
    public function execute(ProductDiscontinuedTransfer $productDiscontinuedTransfer): void
    {
        $this->getFacade()->removeProductAbstractRelationsForLabel($productDiscontinuedTransfer->getFkProduct());
    }
}
