<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\FileManager;

use Spryker\Service\FileManager\Dependency\Service\FileManagerToFileSystemBridge;
use Spryker\Service\Kernel\AbstractBundleDependencyProvider;
use Spryker\Service\Kernel\Container;

class FileManagerServiceDependencyProvider extends AbstractBundleDependencyProvider
{
    const FILE_SYSTEM_SERVICE = 'FILE_SYSTEM_SERVICE';

    /**
     * @param \Spryker\Service\Kernel\Container $container
     *
     * @return \Spryker\Service\Kernel\Container
     */
    public function provideServiceDependencies(Container $container)
    {
        $container = parent::provideServiceDependencies($container);

        $container[static::FILE_SYSTEM_SERVICE] = function ($container) {
            $fileSystemService = $container->getLocator()->fileSystem()->service();
            return new FileManagerToFileSystemBridge($fileSystemService);
        };

        return $container;
    }
}
