<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductReview;

use Generated\Shared\Transfer\ProductReviewRequestTransfer;
use Generated\Shared\Transfer\ProductReviewSearchRequestTransfer;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\ProductReview\ProductReviewFactory getFactory()
 */
class ProductReviewClient extends AbstractClient implements ProductReviewClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductReviewRequestTransfer $productReviewRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ProductReviewResponseTransfer
     */
    public function submitCustomerReview(ProductReviewRequestTransfer $productReviewRequestTransfer)
    {
        return $this->getFactory()
            ->createProductReviewStub()
            ->submitCustomerReview($productReviewRequestTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductReviewSearchRequestTransfer $productReviewSearchRequestTransfer
     *
     * @return array
     */
    public function findProductReviewsInSearch(ProductReviewSearchRequestTransfer $productReviewSearchRequestTransfer)
    {
        $searchQuery = $this->getFactory()->createProductReviewsQueryPlugin($productReviewSearchRequestTransfer);
        $resultFormatters = $this->getFactory()->getProductReviewsSearchResultFormatterPlugins();

        return $this->getFactory()
            ->getSearchClient()
            ->search($searchQuery, $resultFormatters, $productReviewSearchRequestTransfer->getRequestParams());
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductAbstract
     * @param string $localeName
     *
     * @return \Generated\Shared\Transfer\ProductAbstractReviewTransfer|null
     */
    public function findProductAbstractReviewInStorage($idProductAbstract, $localeName)
    {
        return $this->getFactory()
            ->createProductAbstractReviewStorageReader()
            ->findProductAbstractReview($idProductAbstract, $localeName);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return int
     */
    public function getMaximumRating()
    {
        return $this->getFactory()->getConfig()->getMaximumRating();
    }
}
