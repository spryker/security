<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductCategoryStorage\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\ProductCategoryStorage\Business\Storage\ProductCategoryStorageWriter;
use Spryker\Zed\ProductCategoryStorage\ProductCategoryStorageDependencyProvider;

/**
 * @method \Spryker\Zed\ProductCategoryStorage\ProductCategoryStorageConfig getConfig()
 * @method \Spryker\Zed\ProductCategoryStorage\Persistence\ProductCategoryStorageQueryContainerInterface getQueryContainer()
 */
class ProductCategoryStorageBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\ProductCategoryStorage\Business\Storage\ProductCategoryStorageWriterInterface
     */
    public function createProductCategoryStorageWriter()
    {
        return new ProductCategoryStorageWriter(
            $this->getCategoryFacade(),
            $this->getQueryContainer(),
            $this->getStore(),
            $this->getConfig()->isSendingToQueue()
        );
    }

    /**
     * @return \Spryker\Zed\ProductCategoryStorage\Dependency\Facade\ProductCategoryStorageToCategoryBridge
     */
    public function getCategoryFacade()
    {
        return $this->getProvidedDependency(ProductCategoryStorageDependencyProvider::FACADE_CATEGORY);
    }

    /**
     * @return \Spryker\Shared\Kernel\Store
     */
    public function getStore()
    {
        return $this->getProvidedDependency(ProductCategoryStorageDependencyProvider::STORE);
    }
}
