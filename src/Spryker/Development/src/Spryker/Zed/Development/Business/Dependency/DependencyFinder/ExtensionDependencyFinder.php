<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business\Dependency\DependencyFinder;

use Spryker\Zed\Development\Business\Dependency\DependencyContainer\DependencyContainerInterface;
use Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface;
use Spryker\Zed\Development\Business\Module\ModuleFinder\ModuleFinderInterface;

class ExtensionDependencyFinder extends AbstractFileDependencyFinder
{
    public const TYPE_EXTENSION = 'extension';

    /**
     * @var \Generated\Shared\Transfer\ModuleTransfer[]
     */
    protected $executedModules = [];

    /**
     * @var \Spryker\Zed\Development\Business\Module\ModuleFinder\ModuleFinderInterface
     */
    protected $moduleFinder;

    /**
     * @param \Spryker\Zed\Development\Business\Module\ModuleFinder\ModuleFinderInterface $moduleFinder
     */
    public function __construct(ModuleFinderInterface $moduleFinder)
    {
        $this->moduleFinder = $moduleFinder;
    }

    /**
     * @return string
     */
    public function getType(): string
    {
        return static::TYPE_EXTENSION;
    }

    /**
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface $context
     *
     * @return bool
     */
    public function accept(DependencyFinderContextInterface $context): bool
    {
        $moduleTransfer = $context->getModule();
        $splObjectHash = spl_object_hash($moduleTransfer);

        return !isset($this->executedModules[$splObjectHash]);
    }

    /**
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface $context
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyContainer\DependencyContainerInterface $dependencyContainer
     *
     * @return \Spryker\Zed\Development\Business\Dependency\DependencyContainer\DependencyContainerInterface
     */
    public function findDependencies(DependencyFinderContextInterface $context, DependencyContainerInterface $dependencyContainer): DependencyContainerInterface
    {
        $moduleTransfer = $context->getModule();

        $moduleExtensionKey = sprintf('%s.%sExtension', $moduleTransfer->getOrganization()->getName(), $moduleTransfer->getName());

        if ($this->hasExtensionModule($moduleExtensionKey)) {
            $dependencyContainer->addDependency(sprintf('%sExtension', $moduleTransfer->getName()), $this->getType());
        }

        $this->executedModules[spl_object_hash($moduleTransfer)] = true;

        return $dependencyContainer;
    }

    /**
     * @param string $moduleExtensionKey
     *
     * @return bool
     */
    protected function hasExtensionModule(string $moduleExtensionKey): bool
    {
        $moduleTransferCollection = $this->moduleFinder->find();

        return isset($moduleTransferCollection[$moduleExtensionKey]);
    }
}
