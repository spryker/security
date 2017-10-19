<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Transfer\Business;

use Psr\Log\LoggerInterface;
use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\Transfer\Business\Model\DataBuilderGenerator;
use Spryker\Zed\Transfer\Business\Model\GeneratedTransferDirectory;
use Spryker\Zed\Transfer\Business\Model\Generator\ClassDefinition;
use Spryker\Zed\Transfer\Business\Model\Generator\ClassGenerator;
use Spryker\Zed\Transfer\Business\Model\Generator\DataBuilderClassGenerator;
use Spryker\Zed\Transfer\Business\Model\Generator\DataBuilderDefinition;
use Spryker\Zed\Transfer\Business\Model\Generator\DataBuilderDefinitionBuilder;
use Spryker\Zed\Transfer\Business\Model\Generator\DefinitionNormalizer;
use Spryker\Zed\Transfer\Business\Model\Generator\EntityDefinitionNormalizer;
use Spryker\Zed\Transfer\Business\Model\Generator\EntityTransferDefinitionLoader;
use Spryker\Zed\Transfer\Business\Model\Generator\Helper\StandardEnglishPluralizer;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionBuilder;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionFinder;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionLoader;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionMerger;
use Spryker\Zed\Transfer\Business\Model\TransferCleaner;
use Spryker\Zed\Transfer\Business\Model\TransferGenerator;
use Spryker\Zed\Transfer\Business\Model\TransferValidator;
use Spryker\Zed\Transfer\TransferDependencyProvider;

/**
 * @method \Spryker\Zed\Transfer\TransferConfig getConfig()
 */
class TransferBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @param \Psr\Log\LoggerInterface $messenger
     *
     * @return \Spryker\Zed\Transfer\Business\Model\TransferGeneratorInterface
     */
    public function createTransferGenerator(LoggerInterface $messenger)
    {
        return new TransferGenerator(
            $messenger,
            $this->createClassGenerator(),
            $this->createTransferDefinitionBuilder()
        );
    }

    /**
     * @param \Psr\Log\LoggerInterface $messenger
     *
     * @return Model\TransferGeneratorInterface
     */
    public function createEntityTransferGenerator(LoggerInterface $messenger)
    {
        return new TransferGenerator(
            $messenger,
            $this->createClassGenerator(),
            $this->createEntityTransferDefinitionBuilder()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\GeneratorInterface
     */
    protected function createClassGenerator()
    {
        return new ClassGenerator(
            $this->getConfig()->getClassTargetDirectory()
        );
    }

    /**
     * @param \Psr\Log\LoggerInterface $messenger
     *
     * @return \Spryker\Zed\Transfer\Business\Model\DataBuilderGenerator
     */
    public function createDataBuilderGenerator(LoggerInterface $messenger)
    {
        return new DataBuilderGenerator(
            $messenger,
            $this->createDataBuilderClassGenerator(),
            $this->createDataBuilderDefinitionBuilder()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\GeneratorInterface
     */
    protected function createDataBuilderClassGenerator()
    {
        return new DataBuilderClassGenerator(
            $this->getConfig()->getDataBuilderTargetDirectory()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionBuilder
     */
    protected function createTransferDefinitionBuilder()
    {
        return new TransferDefinitionBuilder(
            $this->createLoader(),
            $this->createTransferDefinitionMerger(),
            $this->createClassDefinition()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionBuilder
     */
    protected function createEntityTransferDefinitionBuilder()
    {
        return new TransferDefinitionBuilder(
            $this->createEntityLoader(),
            $this->createTransferDefinitionMerger(),
            $this->createClassDefinition()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\DefinitionBuilderInterface
     */
    protected function createDataBuilderDefinitionBuilder()
    {
        return new DataBuilderDefinitionBuilder(
            $this->createDataBuilderLoader(),
            $this->createTransferDefinitionMerger(),
            $this->createDataBuilderDefinition()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\DataBuilderDefinition
     */
    protected function createDataBuilderDefinition()
    {
        return new DataBuilderDefinition();
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\LoaderInterface
     */
    protected function createLoader()
    {
        return new TransferDefinitionLoader(
            $this->createFinder(),
            $this->createDefinitionNormalizer()
        );
    }

    /**
     * @return Model\Generator\LoaderInterface
     */
    protected function createEntityLoader()
    {
        return new EntityTransferDefinitionLoader(
            $this->createEntityFinder(),
            $this->createEntityDefinitionNormalizer()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\LoaderInterface
     */
    protected function createDataBuilderLoader()
    {
        return new TransferDefinitionLoader(
            $this->createDataBuilderFinder(),
            $this->createDefinitionNormalizer()
        );
    }

    /**
     * @deprecated Use createTransferGeneratedDirectory() instead
     *
     * @return \Spryker\Zed\Transfer\Business\Model\TransferCleanerInterface
     */
    public function createTransferCleaner()
    {
        return new TransferCleaner(
            $this->getConfig()->getClassTargetDirectory()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\GeneratedTransferDirectoryInterface
     */
    public function createTransferGeneratedDirectory()
    {
        return new GeneratedTransferDirectory(
            $this->getConfig()->getClassTargetDirectory(),
            $this->getFileSystem(),
            $this->getFinder()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\GeneratedTransferDirectoryInterface
     */
    public function createDataBuilderGeneratedDirectory()
    {
        return new GeneratedTransferDirectory(
            $this->getConfig()->getDataBuilderTargetDirectory(),
            $this->getFileSystem(),
            $this->getFinder()
        );
    }

    /**
     * @return \Symfony\Component\Filesystem\Filesystem
     */
    protected function getFileSystem()
    {
        return $this->getProvidedDependency(TransferDependencyProvider::SYMFONY_FILE_SYSTEM);
    }

    /**
     * @return \Symfony\Component\Finder\Finder
     */
    protected function getFinder()
    {
        return $this->getProvidedDependency(TransferDependencyProvider::SYMFONY_FINDER);
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\MergerInterface
     */
    protected function createTransferDefinitionMerger()
    {
        return new TransferDefinitionMerger();
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\ClassDefinitionInterface
     */
    protected function createClassDefinition()
    {
        return new ClassDefinition();
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\DefinitionNormalizerInterface
     */
    protected function createDefinitionNormalizer()
    {
        return new DefinitionNormalizer();
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\DefinitionNormalizerInterface
     */
    protected function createEntityDefinitionNormalizer()
    {
        return new EntityDefinitionNormalizer($this->createPluralizer());
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\Helper\PluralizerInterface
     */
    protected function createPluralizer()
    {
        return new StandardEnglishPluralizer();
    }

    /**
     * @param \Psr\Log\LoggerInterface $messenger
     *
     * @return \Spryker\Zed\Transfer\Business\Model\TransferValidatorInterface
     */
    public function createValidator(LoggerInterface $messenger)
    {
        return new TransferValidator(
            $messenger,
            $this->createFinder()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\FinderInterface
     */
    protected function createFinder()
    {
        return new TransferDefinitionFinder(
            $this->getConfig()->getSourceDirectories()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\FinderInterface
     */
    protected function createEntityFinder()
    {
        return new TransferDefinitionFinder(
            $this->getConfig()->getEntitiesSourceDirectories(),
            $this->getConfig()->getEntityFileNamePattern()
        );
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\FinderInterface
     */
    protected function createDataBuilderFinder()
    {
        return new TransferDefinitionFinder(
            $this->getConfig()->getDataBuilderSourceDirectories(),
            $this->getConfig()->getDataBuilderFileNamePattern()
        );
    }
}
