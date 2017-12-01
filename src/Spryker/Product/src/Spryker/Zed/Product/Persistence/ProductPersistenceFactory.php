<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Product\Persistence;

use Orm\Zed\Product\Persistence\SpyProductAbstractLocalizedAttributesQuery;
use Orm\Zed\Product\Persistence\SpyProductAbstractQuery;
use Orm\Zed\Product\Persistence\SpyProductAttributeKeyQuery;
use Orm\Zed\Product\Persistence\SpyProductLocalizedAttributesQuery;
use Orm\Zed\Product\Persistence\SpyProductQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\Product\ProductDependencyProvider;

/**
 * @method \Spryker\Zed\Product\ProductConfig getConfig()
 * @method \Spryker\Zed\Product\Persistence\ProductQueryContainerInterface getQueryContainer()
 */
class ProductPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductAbstractQuery
     */
    public function createProductAbstractQuery()
    {
        return SpyProductAbstractQuery::create();
    }

    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductAbstractLocalizedAttributesQuery
     */
    public function createProductAbstractLocalizedAttributesQuery()
    {
        return SpyProductAbstractLocalizedAttributesQuery::create();
    }

    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductQuery
     */
    public function createProductQuery()
    {
        return SpyProductQuery::create();
    }

    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductLocalizedAttributesQuery
     */
    public function createProductLocalizedAttributesQuery()
    {
        return SpyProductLocalizedAttributesQuery::create();
    }

    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductAttributeKeyQuery
     */
    public function createProductAttributeKeyQuery()
    {
        return SpyProductAttributeKeyQuery::create();
    }

    /**
     * @return \Spryker\Zed\Product\Dependency\QueryContainer\ProductToUrlInterface
     */
    public function getUrlQueryContainer()
    {
        return $this->getProvidedDependency(ProductDependencyProvider::QUERY_CONTAINER_URL);
    }
}
