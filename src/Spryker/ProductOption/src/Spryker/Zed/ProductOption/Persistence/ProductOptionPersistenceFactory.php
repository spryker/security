<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOption\Persistence;

use Orm\Zed\Product\Persistence\SpyProductAbstractQuery;
use Orm\Zed\ProductOption\Persistence\SpyProductAbstractProductOptionGroupQuery;
use Orm\Zed\ProductOption\Persistence\SpyProductOptionGroupQuery;
use Orm\Zed\ProductOption\Persistence\SpyProductOptionValueQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\ProductOption\ProductOptionDependencyProvider;

/**
 * @method \Spryker\Zed\ProductOption\ProductOptionConfig getConfig()
 * @method \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface getQueryContainer()
 */
class ProductOptionPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\ProductOption\Persistence\SpyProductOptionGroupQuery
     */
    public function createProductOptionGroupQuery()
    {
        return SpyProductOptionGroupQuery::create();
    }

    /**
     * @return \Orm\Zed\ProductOption\Persistence\SpyProductOptionValueQuery
     */
    public function createProductOptionValueQuery()
    {
        return SpyProductOptionValueQuery::create();
    }

    /**
     * @return \Orm\Zed\Product\Persistence\SpyProductAbstractQuery
     */
    public function createProductAbstractQuery()
    {
        return SpyProductAbstractQuery::create();
    }

    /**
     * @return \Orm\Zed\ProductOption\Persistence\SpyProductAbstractProductOptionGroupQuery
     */
    public function createProductAbstractProductOptionGroupQuery()
    {
        return SpyProductAbstractProductOptionGroupQuery::create();
    }

    /**
     * @return \Spryker\Zed\ProductOption\Dependency\QueryContainer\ProductOptionToSalesInterface
     */
    public function getSalesQueryContainer()
    {
        return $this->getProvidedDependency(ProductOptionDependencyProvider::QUERY_CONTAINER_SALES);
    }

    /**
     * @return \Spryker\Zed\ProductOption\Dependency\QueryContainer\ProductOptionToCountryInterface
     */
    public function getCountryQueryContainer()
    {
        return $this->getProvidedDependency(ProductOptionDependencyProvider::QUERY_CONTAINER_COUNTRY);
    }
}
