<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductStorage;

use Spryker\Client\Kernel\AbstractFactory;
use Spryker\Client\ProductStorage\Filter\ProductAbstractAttributeMapRestrictionFilter;
use Spryker\Client\ProductStorage\Filter\ProductAbstractAttributeMapRestrictionFilterInterface;
use Spryker\Client\ProductStorage\Mapper\ProductStorageDataMapper;
use Spryker\Client\ProductStorage\Mapper\ProductVariantExpander;
use Spryker\Client\ProductStorage\Storage\ProductAbstractStorageReader;
use Spryker\Client\ProductStorage\Storage\ProductConcreteStorageReader;

class ProductStorageFactory extends AbstractFactory
{
    /**
     * @return \Spryker\Client\ProductStorage\Dependency\Client\ProductStorageToStorageClientInterface
     */
    protected function getStorageClient()
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::CLIENT_STORAGE);
    }

    /**
     * @return \Spryker\Client\ProductStorage\Dependency\Service\ProductStorageToSynchronizationServiceBridge
     */
    public function getSynchronizationService()
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::SERVICE_SYNCHRONIZATION);
    }

    /**
     * @return \Spryker\Client\ProductStorage\Dependency\Client\ProductStorageToLocaleInterface
     */
    public function getLocaleClient()
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::CLIENT_LOCALE);
    }

    /**
     * @return \Spryker\Client\ProductStorage\Storage\ProductConcreteStorageReaderInterface
     */
    public function createProductConcreteStorageReader()
    {
        return new ProductConcreteStorageReader(
            $this->getStorageClient(),
            $this->getSynchronizationService(),
            $this->getProductConcreteRestrictionPlugins()
        );
    }

    /**
     * @return \Spryker\Client\ProductStorage\Storage\ProductAbstractStorageReaderInterface
     */
    public function createProductAbstractStorageReader()
    {
        return new ProductAbstractStorageReader(
            $this->getStorageClient(),
            $this->getSynchronizationService(),
            $this->getStore(),
            $this->createProductAbstractAttributeMapRestrictionFilter(),
            $this->getProductAbstractRestrictionPlugins()
        );
    }

    /**
     * @return \Spryker\Client\ProductStorage\Mapper\ProductStorageDataMapperInterface
     */
    public function createProductStorageDataMapper()
    {
        return new ProductStorageDataMapper(
            $this->getStorageProductExpanderPlugins(),
            $this->createProductAbstractAttributeMapRestrictionFilter()
        );
    }

    /**
     * @return \Spryker\Client\ProductStorage\Mapper\ProductStorageDataMapperInterface
     */
    public function createProductAbstractStorageDataMapper()
    {
        return new ProductStorageDataMapper(
            $this->getStorageProductAbstractExpanderPlugins(),
            $this->createProductAbstractAttributeMapRestrictionFilter()
        );
    }

    /**
     * @return \Spryker\Client\ProductStorage\Mapper\ProductVariantExpanderInterface
     */
    public function createVariantExpander()
    {
        return new ProductVariantExpander($this->createProductConcreteStorageReader());
    }

    /**
     * @return \Spryker\Client\ProductStorage\Filter\ProductAbstractAttributeMapRestrictionFilterInterface
     */
    public function createProductAbstractAttributeMapRestrictionFilter(): ProductAbstractAttributeMapRestrictionFilterInterface
    {
        return new ProductAbstractAttributeMapRestrictionFilter(
            $this->createProductConcreteStorageReader()
        );
    }

    /**
     * @return \Spryker\Client\ProductStorage\Dependency\Plugin\ProductViewExpanderPluginInterface[]
     */
    protected function getStorageProductExpanderPlugins()
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::PLUGIN_PRODUCT_VIEW_EXPANDERS);
    }

    /**
     * @return \Spryker\Shared\Kernel\Store
     */
    public function getStore()
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::STORE);
    }

    /**
     * @return \Spryker\Client\ProductStorageExtension\Dependency\Plugin\ProductAbstractRestrictionPluginInterface[]
     */
    public function getProductAbstractRestrictionPlugins(): array
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::PLUGINS_PRODUCT_ABSTRACT_RESTRICTION);
    }

    /**
     * @return \Spryker\Client\ProductStorageExtension\Dependency\Plugin\ProductConcreteRestrictionPluginInterface[]
     */
    public function getProductConcreteRestrictionPlugins(): array
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::PLUGINS_PRODUCT_CONCRETE_RESTRICTION);
    }

    /**
     * @return \Spryker\Client\ProductStorage\Dependency\Plugin\ProductViewExpanderPluginInterface[]
     */
    public function getStorageProductAbstractExpanderPlugins()
    {
        return $this->getProvidedDependency(ProductStorageDependencyProvider::PLUGIN_PRODUCT_ABSTRACT_VIEW_EXPANDERS);
    }
}
