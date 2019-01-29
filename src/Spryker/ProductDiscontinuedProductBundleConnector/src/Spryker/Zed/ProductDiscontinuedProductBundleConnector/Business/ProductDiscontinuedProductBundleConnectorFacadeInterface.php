<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedProductBundleConnector\Business;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedTransfer;

interface ProductDiscontinuedProductBundleConnectorFacadeInterface
{
    /**
     * Specification:
     *  - Find bundle products related to discontinued simple.
     *  - Mark related bundle product as discontinued.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductDiscontinuedTransfer $productDiscontinuedTransfer
     *
     * @return void
     */
    public function markRelatedBundleAsDiscontinued(ProductDiscontinuedTransfer $productDiscontinuedTransfer): void;

    /**
     * Specification:
     * - Marks bundle as discontinued if one of bundled products is discontinued.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return void
     */
    public function markBundleAsDiscontinuedByBundledProducts(ProductConcreteTransfer $productConcreteTransfer): void;

    /**
     * Specification:
     * - Checks bundled products.
     * - Returns response transfer with success true if all bundled products are not discontinued.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductDiscontinuedTransfer $productDiscontinuedTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function checkBundledProducts(ProductDiscontinuedTransfer $productDiscontinuedTransfer): ProductDiscontinuedResponseTransfer;
}
