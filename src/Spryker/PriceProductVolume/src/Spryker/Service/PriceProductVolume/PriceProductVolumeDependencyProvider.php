<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\PriceProductVolume;

use Spryker\Service\Kernel\AbstractBundleDependencyProvider;
use Spryker\Service\Kernel\Container;
use Spryker\Service\PriceProductVolume\Dependency\Service\PriceProductVolumeToUtilQuantityServiceBridge;

class PriceProductVolumeDependencyProvider extends AbstractBundleDependencyProvider
{
    public const SERVICE_UTIL_QUANTITY = 'SERVICE_UTIL_QUANTITY';

    /**
     * @param \Spryker\Service\Kernel\Container $container
     *
     * @return \Spryker\Service\Kernel\Container
     */
    public function provideServiceDependencies(Container $container): Container
    {
        $container = $this->addUtilQuantityService($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Kernel\Container $container
     *
     * @return \Spryker\Service\Kernel\Container
     */
    protected function addUtilQuantityService(Container $container): Container
    {
        $container[static::SERVICE_UTIL_QUANTITY] = function (Container $container) {
            return new PriceProductVolumeToUtilQuantityServiceBridge(
                $container->getLocator()->utilQuantity()->service()
            );
        };

        return $container;
    }
}
