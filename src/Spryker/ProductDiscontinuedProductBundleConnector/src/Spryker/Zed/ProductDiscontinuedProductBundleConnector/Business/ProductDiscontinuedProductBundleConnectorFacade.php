<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedProductBundleConnector\Business;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductDiscontinuedProductBundleConnector\Business\ProductDiscontinuedProductBundleConnectorBusinessFactory getFactory()
 * @method \Spryker\Zed\ProductDiscontinuedProductBundleConnector\Persistence\ProductDiscontinuedProductBundleConnectorRepositoryInterface getRepository()
 */
class ProductDiscontinuedProductBundleConnectorFacade extends AbstractFacade implements ProductDiscontinuedProductBundleConnectorFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductDiscontinuedTransfer $productDiscontinuedTransfer
     *
     * @return void
     */
    public function markRelatedBundleAsDiscontinued(ProductDiscontinuedTransfer $productDiscontinuedTransfer): void
    {
        $this->getFactory()
            ->createProductBundleDiscontinuedWriter()
            ->discontinueRelatedBundle($productDiscontinuedTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return void
     */
    public function markProductBundleAsDiscontinuedByBundledProducts(ProductConcreteTransfer $productConcreteTransfer): void
    {
        $this->getFactory()
            ->createProductBundleDiscontinuedWriter()
            ->discontinueProductBundleByBundledProducts($productConcreteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductDiscontinuedTransfer $productDiscontinuedTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function checkBundledProducts(ProductDiscontinuedTransfer $productDiscontinuedTransfer): ProductDiscontinuedResponseTransfer
    {
        return $this->getFactory()
            ->createProductBundleDiscontinuedReader()
            ->checkBundledProducts($productDiscontinuedTransfer);
    }
}
