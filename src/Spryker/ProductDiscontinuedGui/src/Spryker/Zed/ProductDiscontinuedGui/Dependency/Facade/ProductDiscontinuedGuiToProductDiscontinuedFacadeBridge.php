<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedGui\Dependency\Facade;

use Generated\Shared\Transfer\ProductDiscontinuedRequestTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer;

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
     * @param \Generated\Shared\Transfer\ProductDiscontinuedRequestTransfer $productDiscontinuedRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function unmarkProductAsDiscontinued(
        ProductDiscontinuedRequestTransfer $productDiscontinuedRequestTransfer
    ): ProductDiscontinuedResponseTransfer {
        return $this->productDiscontinuedFacade->unmarkProductAsDiscontinued($productDiscontinuedRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductDiscontinuedRequestTransfer $productDiscontinuedRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function markProductAsDiscontinued(
        ProductDiscontinuedRequestTransfer $productDiscontinuedRequestTransfer
    ): ProductDiscontinuedResponseTransfer {
        return $this->productDiscontinuedFacade->markProductAsDiscontinued($productDiscontinuedRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductDiscontinuedRequestTransfer $productDiscontinuedRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function findProductDiscontinuedByProductId(
        ProductDiscontinuedRequestTransfer $productDiscontinuedRequestTransfer
    ): ProductDiscontinuedResponseTransfer {
        return $this->productDiscontinuedFacade->findProductDiscontinuedByProductId(
            $productDiscontinuedRequestTransfer
        );
    }
}
