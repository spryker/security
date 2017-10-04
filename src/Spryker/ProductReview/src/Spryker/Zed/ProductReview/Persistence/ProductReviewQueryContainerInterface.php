<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductReview\Persistence;

/**
 * @method \Spryker\Zed\ProductReview\Persistence\ProductReviewPersistenceFactory getFactory()
 */
interface ProductReviewQueryContainerInterface
{

    /**
     * @api
     *
     * @param int $idProductReview
     *
     * @return \Orm\Zed\ProductReview\Persistence\SpyProductReviewQuery
     */
    public function queryProductReviewById($idProductReview);

    /**
     * @api
     *
     * @return \Orm\Zed\ProductReview\Persistence\SpyProductReviewQuery
     */
    public function queryProductReview();

}
