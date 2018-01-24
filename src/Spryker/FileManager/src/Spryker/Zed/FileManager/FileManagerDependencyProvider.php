<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\FileManager;

use Spryker\Zed\FileManager\Dependency\Service\FileManagerToFileSystemBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

class FileManagerDependencyProvider extends AbstractBundleDependencyProvider
{
    const SERVICE_FILE_SYSTEM = 'SERVICE_FILE_SYSTEM';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideBusinessLayerDependencies(Container $container)
    {
        $container[static::SERVICE_FILE_SYSTEM] = function (Container $container) {
            $fileSystemService = $container->getLocator()->fileSystem()->service();
            return new FileManagerToFileSystemBridge($fileSystemService);
        };

        return $container;
    }
}
