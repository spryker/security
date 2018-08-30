<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductResourceAliasStorage\Persistence;

use Orm\Zed\Product\Persistence\Map\SpyProductAbstractTableMap;
use Orm\Zed\Product\Persistence\Map\SpyProductTableMap;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;

/**
 * @method \Spryker\Zed\ProductResourceAliasStorage\Persistence\ProductResourceAliasStoragePersistenceFactory getFactory()
 */
class ProductResourceAliasStorageRepository extends AbstractRepository implements ProductResourceAliasStorageRepositoryInterface
{
    protected const KEY_SKU = 'sku';

    /**
     * @param int[] $productAbstractIds
     *
     * @return \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage[]
     */
    public function getProductAbstractStorageEntities(array $productAbstractIds): array
    {
        return $this->getFactory()
            ->getProductAbstractStoragePropelQuery()
            ->filterByFkProductAbstract_In($productAbstractIds)
            ->find()
            ->getData();
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return string[]
     */
    public function getProductAbstractSkuList(array $productAbstractIds): array
    {
        return $this->getFactory()
            ->getProductAbstractPropelQuery()
            ->filterByIdProductAbstract_In($productAbstractIds)
            ->select([SpyProductAbstractTableMap::COL_ID_PRODUCT_ABSTRACT, SpyProductAbstractTableMap::COL_SKU => static::KEY_SKU])
            ->find()
            ->toArray(SpyProductAbstractTableMap::COL_ID_PRODUCT_ABSTRACT);
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage[]
     */
    public function getProductConcreteStorageEntities(array $productConcreteIds): array
    {
        return $this->getFactory()
            ->getProductConcreteStoragePropelQuery()
            ->filterByFkProduct_In($productConcreteIds)
            ->find()
            ->getData();
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return string[]
     */
    public function getProductConcreteSkuList(array $productConcreteIds): array
    {
        return $this->getFactory()
            ->getProductPropelQuery()
            ->filterByIdProduct_In($productConcreteIds)
            ->select([SpyProductTableMap::COL_ID_PRODUCT, SpyProductTableMap::COL_SKU => static::KEY_SKU])
            ->find()
            ->toArray(SpyProductTableMap::COL_ID_PRODUCT);
    }
}
