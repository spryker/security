<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Permission;

use Spryker\Client\Kernel\AbstractFactory;
use Spryker\Client\Permission\Dependency\Client\PermissionToZedRequestClientInterface;
use Spryker\Client\Permission\PermissionExecutor\PermissionExecutor;
use Spryker\Client\Permission\PermissionExecutor\PermissionExecutorInterface;
use Spryker\Client\Permission\PermissionFinder\PermissionFinder;
use Spryker\Client\Permission\PermissionFinder\PermissionFinderInterface;
use Spryker\Client\Permission\Zed\PermissionStub;
use Spryker\Client\Permission\Zed\PermissionStubInterface;
use Spryker\Client\PermissionExtension\Dependency\Plugin\PermissionStoragePluginInterface;

class PermissionFactory extends AbstractFactory
{
    /**
     * @return \Spryker\Client\Permission\PermissionFinder\PermissionFinderInterface
     */
    public function createPermissionFinder(): PermissionFinderInterface
    {
        return new PermissionFinder(
            $this->getPermissionPlugins()
        );
    }

    /**
     * @return \Spryker\Client\Permission\PermissionExecutor\PermissionExecutorInterface
     */
    public function createPermissionExecutor(): PermissionExecutorInterface
    {
        return new PermissionExecutor(
            $this->getPermissionStoragePlugin(),
            $this->createPermissionFinder()
        );
    }

    /**
     * @return \Spryker\Client\Permission\Zed\PermissionStubInterface
     */
    public function createZedPermissionStub(): PermissionStubInterface
    {
        return new PermissionStub($this->getZedRequestClient());
    }

    /**
     * @return \Spryker\Shared\PermissionExtension\Dependency\Plugin\PermissionPluginInterface[]
     */
    protected function getPermissionPlugins(): array
    {
        return $this->getProvidedDependency(PermissionDependencyProvider::PLUGINS_PERMISSION);
    }

    /**
     * @return \Spryker\Client\PermissionExtension\Dependency\Plugin\PermissionStoragePluginInterface
     */
    protected function getPermissionStoragePlugin(): PermissionStoragePluginInterface
    {
        return $this->getProvidedDependency(PermissionDependencyProvider::PLUGIN_PERMISSION_STORAGE);
    }

    /**
     * @return \Spryker\Client\Permission\Dependency\Client\PermissionToZedRequestClientInterface
     */
    protected function getZedRequestClient(): PermissionToZedRequestClientInterface
    {
        return $this->getProvidedDependency(PermissionDependencyProvider::CLIENT_ZED_REQUEST);
    }
}
