<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductImageStorage;

use Spryker\Client\Kernel\AbstractFactory;
use Spryker\Client\ProductImageStorage\Expander\ProductViewImageExpander;
use Spryker\Client\ProductImageStorage\Storage\ProductAbstractImageStorageReader;
use Spryker\Client\ProductImageStorage\Storage\ProductConcreteImageStorageReader;
use Spryker\Client\ProductImageStorage\Storage\ProductImageStorageKeyGenerator;

class ProductImageStorageFactory extends AbstractFactory
{
    /**
     * @return \Spryker\Client\ProductImageStorage\Expander\ProductViewImageExpanderInterface
     */
    public function createProductViewImageExpander()
    {
        return new ProductViewImageExpander($this->createProductAbstractImageStorageReader(), $this->createProductConcreteImageStorageReader());
    }

    /**
     * @return \Spryker\Client\ProductImageStorage\Storage\ProductAbstractImageStorageReaderInterface
     */
    protected function createProductAbstractImageStorageReader()
    {
        return new ProductAbstractImageStorageReader($this->getStorage(), $this->createProductImageStorageKeyGenerator());
    }

    /**
     * @return \Spryker\Client\ProductImageStorage\Storage\ProductConcreteImageStorageReaderInterface
     */
    protected function createProductConcreteImageStorageReader()
    {
        return new ProductConcreteImageStorageReader($this->getStorage(), $this->createProductImageStorageKeyGenerator());
    }

    /**
     * @return \Spryker\Client\ProductImageStorage\Storage\ProductImageStorageKeyGeneratorInterface
     */
    protected function createProductImageStorageKeyGenerator()
    {
        return new ProductImageStorageKeyGenerator($this->getSynchronizationService(), $this->getStore());
    }

    /**
     * @return \Spryker\Client\ProductImageStorage\Dependency\Client\ProductImageStorageToStorageInterface
     */
    protected function getStorage()
    {
        return $this->getProvidedDependency(ProductImageStorageDependencyProvider::CLIENT_STORAGE);
    }

    /**
     * @return \Spryker\Client\ProductImageStorage\Dependency\Service\ProductImageStorageToSynchronizationServiceBridge
     */
    protected function getSynchronizationService()
    {
        return $this->getProvidedDependency(ProductImageStorageDependencyProvider::SERVICE_SYNCHRONIZATION);
    }

    /**
     * @return \Spryker\Shared\Kernel\Store
     */
    protected function getStore()
    {
        return $this->getProvidedDependency(ProductImageStorageDependencyProvider::STORE);
    }
}
