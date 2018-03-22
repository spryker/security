<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAttribute;

use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;
use Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToGlossaryBridge;
use Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToLocaleBridge;
use Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToProductBridge;
use Spryker\Zed\ProductAttribute\Dependency\Service\ProductAttributeToUtilEncodingBridge;

class ProductAttributeDependencyProvider extends AbstractBundleDependencyProvider
{
    const FACADE_LOCALE = 'FACADE_LOCALE';
    const FACADE_GLOSSARY = 'FACADE_GLOSSARY';
    const FACADE_PRODUCT = 'FACADE_PRODUCT';

    const SERVICE_UTIL_ENCODING = 'SERVICE_UTIL_ENCODING';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container = $this->addUtilEncodingService($container);
        $container = $this->addLocaleFacade($container);
        $container = $this->addGlossaryFacade($container);
        $container = $this->addProductFacade($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addUtilEncodingService($container)
    {
        $container[static::SERVICE_UTIL_ENCODING] = function (Container $container) {
            return new ProductAttributeToUtilEncodingBridge($container->getLocator()->utilEncoding()->service());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addLocaleFacade(Container $container)
    {
        $container[static::FACADE_LOCALE] = function (Container $container) {
            return new ProductAttributeToLocaleBridge($container->getLocator()->locale()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addGlossaryFacade(Container $container)
    {
        $container[static::FACADE_GLOSSARY] = function (Container $container) {
            return new ProductAttributeToGlossaryBridge($container->getLocator()->glossary()->facade());
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addProductFacade(Container $container)
    {
        $container[static::FACADE_PRODUCT] = function (Container $container) {
            return new ProductAttributeToProductBridge($container->getLocator()->product()->facade());
        };

        return $container;
    }
}
