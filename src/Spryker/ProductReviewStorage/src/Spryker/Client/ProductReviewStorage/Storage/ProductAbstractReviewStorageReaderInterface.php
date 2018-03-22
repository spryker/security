<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductReviewStorage\Storage;

interface ProductAbstractReviewStorageReaderInterface
{
    /**
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\ProductReviewStorageTransfer|null
     */
    public function findProductAbstractReview($idProductAbstract);
}
