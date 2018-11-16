<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\FileManagerGui;

use Orm\Zed\FileManager\Persistence\SpyFileInfoQuery;
use Orm\Zed\FileManager\Persistence\SpyFileQuery;
use Orm\Zed\FileManager\Persistence\SpyMimeTypeQuery;
use Spryker\Zed\FileManagerGui\Dependency\Facade\FileManagerGuiToFileManagerFacadeBridge;
use Spryker\Zed\FileManagerGui\Dependency\Facade\FileManagerGuiToLocaleFacadeBridge;
use Spryker\Zed\Kernel\AbstractBundleDependencyProvider;
use Spryker\Zed\Kernel\Container;

/**
 * @method \Spryker\Zed\FileManagerGui\FileManagerGuiConfig getConfig()
 */
class FileManagerGuiDependencyProvider extends AbstractBundleDependencyProvider
{
    public const FACADE_FILE_MANAGER = 'FACADE_FILE_MANAGER';
    public const FACADE_LOCALE = 'FACADE_LOCALE';
    public const PROPEL_QUERY_FILE = 'PROPEL_QUERY_FILE';
    public const PROPEL_QUERY_FILE_INFO = 'PROPEL_QUERY_FILE_INFO';
    public const PROPEL_QUERY_MIME_TYPE = 'PROPEL_QUERY_MIME_TYPE';

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    public function provideCommunicationLayerDependencies(Container $container)
    {
        $container = $this->addFileManagerFacade($container);
        $container = $this->addLocaleFacade($container);
        $container = $this->addQueries($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addFileManagerFacade(Container $container)
    {
        $container[static::FACADE_FILE_MANAGER] = function (Container $container) {
            return new FileManagerGuiToFileManagerFacadeBridge(
                $container->getLocator()->fileManager()->facade()
            );
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
            return new FileManagerGuiToLocaleFacadeBridge(
                $container->getLocator()->locale()->facade()
            );
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addQueries(Container $container)
    {
        $container = $this->addFileQuery($container);
        $container = $this->addFileInfoQuery($container);
        $container = $this->addMimeTypeQuery($container);

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addFileQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_FILE] = function (Container $container) {
            return SpyFileQuery::create();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addFileInfoQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_FILE_INFO] = function (Container $container) {
            return SpyFileInfoQuery::create();
        };

        return $container;
    }

    /**
     * @param \Spryker\Zed\Kernel\Container $container
     *
     * @return \Spryker\Zed\Kernel\Container
     */
    protected function addMimeTypeQuery(Container $container): Container
    {
        $container[static::PROPEL_QUERY_MIME_TYPE] = function (Container $container) {
            return SpyMimeTypeQuery::create();
        };

        return $container;
    }
}
