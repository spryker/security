<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\FileManager;

use Spryker\Service\FileManager\Dependency\Service\FileManagerToFileSystemServiceBridge;
use Spryker\Service\Kernel\AbstractBundleDependencyProvider;
use Spryker\Service\Kernel\Container;

/**
 * @method \Spryker\Service\FileManager\FileManagerConfig getConfig()
 */
class FileManagerDependencyProvider extends AbstractBundleDependencyProvider
{
    public const SERVICE_FILE_SYSTEM = 'SERVICE_FILE_SYSTEM';

    /**
     * @param \Spryker\Service\Kernel\Container $container
     *
     * @return \Spryker\Service\Kernel\Container
     */
    public function provideServiceDependencies(Container $container)
    {
        $container = $this->addFileSystemService($container);

        return $container;
    }

    /**
     * @param \Spryker\Service\Kernel\Container $container
     *
     * @return \Spryker\Service\Kernel\Container
     */
    protected function addFileSystemService(Container $container)
    {
        $container[static::SERVICE_FILE_SYSTEM] = function ($container) {
            return new FileManagerToFileSystemServiceBridge(
                $container->getLocator()->fileSystem()->service()
            );
        };

        return $container;
    }
}
