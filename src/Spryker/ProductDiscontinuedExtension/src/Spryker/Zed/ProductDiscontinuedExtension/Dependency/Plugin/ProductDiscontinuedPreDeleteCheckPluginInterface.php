<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedExtension\Dependency\Plugin;

use Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedTransfer;

interface ProductDiscontinuedPreDeleteCheckPluginInterface
{
    /**
     * Specification:
     *  - This plugin is executed before removing discontinued status from the product.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductDiscontinuedTransfer $productDiscontinuedTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function execute(ProductDiscontinuedTransfer $productDiscontinuedTransfer): ProductDiscontinuedResponseTransfer;
}
