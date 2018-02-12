<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductLabelStorage\Persistence;

use Orm\Zed\ProductLabelStorage\Persistence\SpyProductAbstractLabelStorageQuery;
use Orm\Zed\ProductLabelStorage\Persistence\SpyProductLabelDictionaryStorageQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\ProductLabelStorage\ProductLabelStorageDependencyProvider;

/**
 * @method \Spryker\Zed\ProductLabelStorage\ProductLabelStorageConfig getConfig()
 * @method \Spryker\Zed\ProductLabelStorage\Persistence\ProductLabelStorageQueryContainerInterface getQueryContainer()
 */
class ProductLabelStoragePersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Spryker\Zed\ProductLabelStorage\Dependency\QueryContainer\ProductLabelStorageToProductLabelQueryContainerInterface
     */
    public function getProductLabelQuery()
    {
        return $this->getProvidedDependency(ProductLabelStorageDependencyProvider::QUERY_CONTAINER_PRODUCT_LABEL);
    }

    /**
     * @return \Spryker\Zed\ProductLabelStorage\Dependency\QueryContainer\ProductLabelStorageToProductQueryContainerInterface
     */
    public function getProductQueryContainer()
    {
        return $this->getProvidedDependency(ProductLabelStorageDependencyProvider::QUERY_CONTAINER_PRODUCT);
    }

    /**
     * @return \Orm\Zed\ProductLabelStorage\Persistence\SpyProductAbstractLabelStorageQuery
     */
    public function createSpyProductAbstractLabelStorageQuery()
    {
        return SpyProductAbstractLabelStorageQuery::create();
    }

    /**
     * @return \Orm\Zed\ProductLabelStorage\Persistence\SpyProductLabelDictionaryStorageQuery
     */
    public function createSpyProductLabelDictionaryStorageQuery()
    {
        return SpyProductLabelDictionaryStorageQuery::create();
    }
}
