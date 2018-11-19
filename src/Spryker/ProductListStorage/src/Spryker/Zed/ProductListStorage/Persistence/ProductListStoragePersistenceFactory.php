<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductListStorage\Persistence;

use Orm\Zed\Product\Persistence\SpyProductQuery;
use Orm\Zed\ProductCategory\Persistence\SpyProductCategoryQuery;
use Orm\Zed\ProductList\Persistence\SpyProductListProductConcreteQuery;
use Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorageQuery;
use Orm\Zed\ProductListStorage\Persistence\SpyProductConcreteProductListStorageQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\ProductListStorage\ProductListStorageDependencyProvider;

/**
 * @method \Spryker\Zed\ProductListStorage\ProductListStorageConfig getConfig()
 * @method \Spryker\Zed\ProductListStorage\Persistence\ProductListStorageRepositoryInterface getRepository()
 */
class ProductListStoragePersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductAbstractProductListStorageQuery
     */
    public function createProductAbstractProductListStorageQuery(): SpyProductAbstractProductListStorageQuery
    {
        return SpyProductAbstractProductListStorageQuery::create();
    }

    /**
     * @return \Orm\Zed\ProductListStorage\Persistence\SpyProductConcreteProductListStorageQuery
     */
    public function createProductConcreteProductListStorageQuery(): SpyProductConcreteProductListStorageQuery
    {
        return SpyProductConcreteProductListStorageQuery::create();
    }

    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductQuery
     */
    public function getProductPropelQuery(): SpyProductQuery
    {
        return $this->getProvidedDependency(ProductListStorageDependencyProvider::PROPEL_QUERY_PRODUCT);
    }

    /**
     * @return \Orm\Zed\ProductCategory\Persistence\SpyProductCategoryQuery
     */
    public function getProductCategoryPropelQuery(): SpyProductCategoryQuery
    {
        return $this->getProvidedDependency(ProductListStorageDependencyProvider::PROPEL_QUERY_PRODUCT_CATEGORY);
    }

    /**
     * @return \Orm\Zed\ProductList\Persistence\SpyProductListProductConcreteQuery
     */
    public function getProductListProductConcretePropelQuery(): SpyProductListProductConcreteQuery
    {
        return $this->getProvidedDependency(ProductListStorageDependencyProvider::PROPEL_QUERY_PRODUCT_LIST_PRODUCT_CONCRETE);
    }
}
