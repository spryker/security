<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedGui\Dependency\Facade;

use Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer;
use Generated\Shared\Transfer\ProductDiscontinueRequestTransfer;

class ProductDiscontinuedGuiToProductDiscontinuedFacadeBridge implements ProductDiscontinuedGuiToProductDiscontinuedFacadeInterface
{
    /**
     * @var \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedFacadeInterface
     */
    protected $productDiscontinuedFacade;

    /**
     * @param \Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinuedFacadeInterface $productDiscontinuedFacade
     */
    public function __construct($productDiscontinuedFacade)
    {
        $this->productDiscontinuedFacade = $productDiscontinuedFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductDiscontinueRequestTransfer $productDiscontinueRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function unmarkProductAsDiscontinued(
        ProductDiscontinueRequestTransfer $productDiscontinueRequestTransfer
    ): ProductDiscontinuedResponseTransfer {
        return $this->productDiscontinuedFacade->unmarkProductAsDiscontinued($productDiscontinueRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductDiscontinueRequestTransfer $productDiscontinueRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function markProductAsDiscontinued(
        ProductDiscontinueRequestTransfer $productDiscontinueRequestTransfer
    ): ProductDiscontinuedResponseTransfer {
        return $this->productDiscontinuedFacade->markProductAsDiscontinued($productDiscontinueRequestTransfer);
    }

    /**
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function findProductDiscontinuedByProductId(int $idProduct): ProductDiscontinuedResponseTransfer
    {
        return $this->productDiscontinuedFacade->findProductDiscontinuedByProductId($idProduct);
    }
}
