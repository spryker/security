<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOptionStorage\Persistence;

use Orm\Zed\ProductOptionStorage\Persistence\SpyProductAbstractOptionStorageQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\ProductOptionStorage\ProductOptionStorageDependencyProvider;

/**
 * @method \Spryker\Zed\ProductOptionStorage\ProductOptionStorageConfig getConfig()
 * @method \Spryker\Zed\ProductOptionStorage\Persistence\ProductOptionStorageQueryContainerInterface getQueryContainer()
 */
class ProductOptionStoragePersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Spryker\Zed\ProductOptionStorage\Dependency\QueryContainer\ProductOptionStorageToProductOptionQueryContainerInterface
     */
    public function getProductOptionQuery()
    {
        return $this->getProvidedDependency(ProductOptionStorageDependencyProvider::QUERY_CONTAINER_PRODUCT_OPTION);
    }

    /**
     * @return \Spryker\Zed\ProductOptionStorage\Dependency\QueryContainer\ProductOptionStorageToProductQueryContainerInterface
     */
    public function getProductQueryContainer()
    {
        return $this->getProvidedDependency(ProductOptionStorageDependencyProvider::QUERY_CONTAINER_PRODUCT);
    }

    /**
     * @return \Orm\Zed\ProductOptionStorage\Persistence\SpyProductAbstractOptionStorageQuery
     */
    public function createSpyProductAbstractStorageQuery()
    {
        return SpyProductAbstractOptionStorageQuery::create();
    }
}
