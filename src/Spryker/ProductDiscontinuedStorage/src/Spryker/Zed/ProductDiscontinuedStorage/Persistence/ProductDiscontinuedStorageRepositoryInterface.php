<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedStorage\Persistence;

interface ProductDiscontinuedStorageRepositoryInterface
{
    /**
     * @param int[] $productDiscontinuedIds
     *
     * @return \Orm\Zed\ProductDiscontinuedStorage\Persistence\SpyProductDiscontinuedStorage[]
     */
    public function findProductDiscontinuedStorageEntitiesByIds(array $productDiscontinuedIds): array;

    /**
     * @return \Orm\Zed\ProductDiscontinuedStorage\Persistence\SpyProductDiscontinuedStorage[]
     */
    public function findAllProductDiscontinuedStorageEntities(): array;
}
