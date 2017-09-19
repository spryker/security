<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductReview\Zed;

use Generated\Shared\Transfer\ProductReviewRequestTransfer;
use Spryker\Client\ProductReview\Dependency\Client\ProductReviewToZedRequestBridge;

class ProductReviewStub implements ProductReviewStubInterface
{

    /**
     * @var \Spryker\Client\ProductReview\Dependency\Client\ProductReviewToZedRequestBridge
     */
    protected $zedRequestClient;

    /**
     * @param \Spryker\Client\ProductReview\Dependency\Client\ProductReviewToZedRequestBridge $zedRequestClient
     */
    public function __construct(ProductReviewToZedRequestBridge $zedRequestClient)
    {
        $this->zedRequestClient = $zedRequestClient;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductReviewRequestTransfer $productReviewRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductReviewResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function submitCustomerReview(ProductReviewRequestTransfer $productReviewRequestTransfer)
    {
        return $this->zedRequestClient->call('/product-review/gateway/submit-customer-review', $productReviewRequestTransfer);
    }

}
