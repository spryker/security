<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Business;

interface ProductPackagingUnitStorageFacadeInterface
{
    /**
     * Specification:
     * - Saves the provided product abstract IDs related ProductAbstractPackaging objects to storage table.
     * - Sends a copy of data to synchronization queue.
     *
     * @api
     *
     * @param int[] $productAbstractIds
     *
     * @return void
     */
    public function publishProductAbstractPackaging(array $productAbstractIds): void;

    /**
     * Specification:
     * - Finds and deletes ProductPackaging storage entities by productAbstractIds
     * - Sends delete message to synchronization queue.
     *
     * @api
     *
     * @param int[] $productAbstractIds
     *
     * @return void
     */
    public function unpublishProductAbstractPackaging(array $productAbstractIds): void;

    /**
     * Specification:
     * - Retrieves the list of product abstract IDs which are associated with any of the provided packaging unit type IDs.
     *
     * @api
     *
     * @param int[] $productPackagingUnitTypeIds
     *
     * @return int[]
     */
    public function findProductAbstractIdsByProductPackagingUnitTypeIds(array $productPackagingUnitTypeIds): array;
}
