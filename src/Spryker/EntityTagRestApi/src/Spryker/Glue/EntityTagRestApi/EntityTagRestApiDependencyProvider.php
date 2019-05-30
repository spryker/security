<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\EntityTagRestApi;

use Spryker\Glue\EntityTagRestApi\Dependency\Client\EntityTagRestApiToEntityTagClientBridge;
use Spryker\Glue\EntityTagRestApi\Dependency\Client\EntityTagRestApiToStorageClientBridge;
use Spryker\Glue\Kernel\AbstractBundleDependencyProvider;
use Spryker\Glue\Kernel\Container;

class EntityTagRestApiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const CLIENT_STORAGE = 'CLIENT_STORAGE';
    public const CLIENT_ENTITY_TAG = 'CLIENT_ENTITY_TAG';

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addStorageClient(Container $container): Container
    {
        $container[static::CLIENT_STORAGE] = function (Container $container) {
            return new EntityTagRestApiToStorageClientBridge(
                $container->getLocator()->storage()->client()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addEntityTagClient(Container $container): Container
    {
        $container[static::CLIENT_ENTITY_TAG] = function (Container $container) {
            return new EntityTagRestApiToEntityTagClientBridge(
                $container->getLocator()->entityTag()->client()
            );
        };

        return $container;
    }
}
