<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductListStorage\Persistence;

use Generated\Shared\Transfer\FilterTransfer;
use Propel\Runtime\Collection\ObjectCollection;

interface ProductListStorageRepositoryInterface
{
    /**
     * @param int[] $productConcreteIds
     *
     * @return int[]
     */
    public function findProductAbstractIdsByProductConcreteIds(array $productConcreteIds): array;

    /**
     * @param int[] $productAbstractIds
     *
     * @return int[]
     */
    public function findProductConcreteIdsByProductAbstractIds(array $productAbstractIds): array;

    /**
     * @param int[] $productAbstractIds
     *
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[]
     */
    public function findProductAbstractProductListStorageEntities(array $productAbstractIds): array;

    /**
     * @param int[] $productConcreteIds
     *
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductConcreteProductListStorage[]
     */
    public function findProductConcreteProductListStorageEntities(array $productConcreteIds): array;

    /**
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[]
     */
    public function findAllProductAbstractProductListStorageEntities(): array;

    /**
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductConcreteProductListStorage[]
     */
    public function findAllProductConcreteProductListStorageEntities(): array;

    /**
     * @param int[] $productListIds
     *
     * @return int[]
     */
    public function findProductConcreteIdsByProductListIds(array $productListIds): array;

    /**
     * @param array $categoryIds
     *
     * @return array
     */
    public function getProductAbstractIdsByCategoryIds(array $categoryIds): array;

    /**
     * @param \Generated\Shared\Transfer\FilterTransfer $filterTransfer
     * @param int[] $productConcreteIds
     *
     * @return \Propel\Runtime\Collection\ObjectCollection|\Orm\Zed\ProductListStorage\Persistence\SpyProductConcreteProductListStorage[]
     */
    public function findFilteredProductConcreteProductListStorageEntities(FilterTransfer $filterTransfer, array $productConcreteIds = []): ObjectCollection;

    /**
     * @param \Generated\Shared\Transfer\FilterTransfer $filterTransfer
     * @param int[] $productAbstractIds
     *
     * @return \Propel\Runtime\Collection\ObjectCollection|\Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorage[]
     */
    public function findFilteredProductAbstractProductListStorageEntities(FilterTransfer $filterTransfer, array $productAbstractIds = []): ObjectCollection;
}
