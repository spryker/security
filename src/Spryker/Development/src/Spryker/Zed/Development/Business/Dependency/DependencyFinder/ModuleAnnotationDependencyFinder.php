<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business\Dependency\DependencyFinder;

use Spryker\Zed\Development\Business\Dependency\DependencyContainer\DependencyContainerInterface;
use Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface;

class ModuleAnnotationDependencyFinder implements DependencyFinderInterface
{
    public const TYPE = 'module-annotation';

    /**
     * @var string[]
     */
    protected $acceptedFileNames = [
        'Repository.php',
        'RepositoryInterface.php',
        'QueryContainer.php',
        'QueryContainerInterface.php',
        'EntityManager.php',
        'EntityManagerInterface.php',
    ];

    /**
     * @return string
     */
    public function getType(): string
    {
        return static::TYPE;
    }

    /**
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface $context
     *
     * @return bool
     */
    public function accept(DependencyFinderContextInterface $context): bool
    {
        if ($context->getDependencyType() !== null && $context->getDependencyType() !== $this->getType()) {
            return false;
        }

        if ($context->getFileInfo()->getExtension() !== 'php') {
            return false;
        }

        if (!$this->isAcceptedFile($context)) {
            return false;
        }

        return true;
    }

    /**
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface $context
     *
     * @return bool
     */
    protected function isAcceptedFile(DependencyFinderContextInterface $context): bool
    {
        $isAccepted = false;
        foreach ($this->acceptedFileNames as $fileName) {
            $isAccepted = substr($context->getFileInfo()->getFilename(), - strlen($fileName)) === $fileName;
        }

        return $isAccepted;
    }

    /**
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyFinder\Context\DependencyFinderContextInterface $context
     * @param \Spryker\Zed\Development\Business\Dependency\DependencyContainer\DependencyContainerInterface $dependencyContainer
     *
     * @return \Spryker\Zed\Development\Business\Dependency\DependencyContainer\DependencyContainerInterface
     */
    public function findDependencies(DependencyFinderContextInterface $context, DependencyContainerInterface $dependencyContainer): DependencyContainerInterface
    {
        if (preg_match_all('/@module\s([a-z-A-Z]*)/', $context->getFileInfo()->getContents(), $matches, PREG_SET_ORDER) !== false) {
            foreach ($matches as $match) {
                $dependencyContainer->addDependency($match[1], $this->getType());
            }
        }

        return $dependencyContainer;
    }
}
