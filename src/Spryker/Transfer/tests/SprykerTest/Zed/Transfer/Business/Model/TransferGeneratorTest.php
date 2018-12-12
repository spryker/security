<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Transfer\Business\Model;

use Codeception\Test\Unit;
use Spryker\Zed\Transfer\Business\Model\Generator\ClassDefinition;
use Spryker\Zed\Transfer\Business\Model\Generator\ClassGenerator;
use Spryker\Zed\Transfer\Business\Model\Generator\DefinitionNormalizer;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionBuilder;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionFinder;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionLoader;
use Spryker\Zed\Transfer\Business\Model\Generator\TransferDefinitionMerger;
use Spryker\Zed\Transfer\Business\Model\TransferGenerator;
use Symfony\Component\Console\Logger\ConsoleLogger;
use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Transfer
 * @group Business
 * @group Model
 * @group TransferGeneratorTest
 * Add your own group annotations below this line
 */
class TransferGeneratorTest extends Unit
{
    /**
     * @return void
     */
    public function testExecuteShouldGenerateExpectedTransfer()
    {
        $sourceDirectories = [
            __DIR__ . '/Fixtures/Shared/Test/Transfer/',
        ];
        $definitionBuilder = $this->getDefinitionBuilder($sourceDirectories);
        $this->assertCount(1, $definitionBuilder->getDefinitions(), 'Expected to get 1 class definition.');

        $messenger = $this->getMessenger();
        $generator = $this->getClassGenerator();

        $transferGenerator = new TransferGenerator($messenger, $generator, $definitionBuilder);
        $transferGenerator->execute();

        $this->assertFileExists($this->getTargetDirectory() . 'CatFaceTransfer.php');
        $this->assertSame(
            file_get_contents(__DIR__ . '/test_files/expected.transfer.php'),
            file_get_contents($this->getTargetDirectory() . 'CatFaceTransfer.php')
        );
    }

    /**
     * @return void
     */
    public function testExecuteShouldGenerateExpectedMergedTransfer()
    {
        $sourceDirectories = [
            __DIR__ . '/Fixtures/Project/Test/Transfer/',
            __DIR__ . '/Fixtures/Vendor/Test2/Transfer/',
        ];
        $definitionBuilder = $this->getDefinitionBuilder($sourceDirectories);
        $this->assertCount(2, $definitionBuilder->getDefinitions(), 'Expected to get 2 class definitions.');

        $messenger = $this->getMessenger();
        $generator = $this->getClassGenerator();

        $transferGenerator = new TransferGenerator($messenger, $generator, $definitionBuilder);
        $transferGenerator->execute();

        $this->assertFileExists($this->getTargetDirectory() . 'FooBarTransfer.php');
        $this->assertSame(
            file_get_contents(__DIR__ . '/test_files/expected.merged.transfer.php'),
            file_get_contents($this->getTargetDirectory() . 'FooBarTransfer.php')
        );

        $this->assertFileExists($this->getTargetDirectory() . 'AnEmptyOneTransfer.php');
    }

    /**
     * @return void
     */
    public function testExecuteShouldGenerateExpectedDeprecatedTransfer()
    {
        $sourceDirectories = [
            __DIR__ . '/Fixtures/Shared/Deprecated/Transfer/',
        ];
        $definitionBuilder = $this->getDefinitionBuilder($sourceDirectories);
        $this->assertCount(1, $definitionBuilder->getDefinitions(), 'Expected to get 1 class definition.');

        $messenger = $this->getMessenger();
        $generator = $this->getClassGenerator();

        $transferGenerator = new TransferGenerator($messenger, $generator, $definitionBuilder);
        $transferGenerator->execute();

        $this->assertFileExists($this->getTargetDirectory() . 'DeprecatedFooBarTransfer.php');
        $this->assertSame(
            file_get_contents(__DIR__ . '/test_files/expected.deprecated.transfer.php'),
            file_get_contents($this->getTargetDirectory() . 'DeprecatedFooBarTransfer.php')
        );
    }

    /**
     * @return void
     */
    public function testExecuteShouldGenerateExpectedMergedDeprecatedTransfer()
    {
        $sourceDirectories = [
            __DIR__ . '/Fixtures/Vendor/Deprecated/Transfer/',
            __DIR__ . '/Fixtures/Project/Deprecated/Transfer/',
        ];
        $definitionBuilder = $this->getDefinitionBuilder($sourceDirectories);
        $this->assertCount(1, $definitionBuilder->getDefinitions(), 'Expected to get 1 class definition.');

        $messenger = $this->getMessenger();
        $generator = $this->getClassGenerator();

        $transferGenerator = new TransferGenerator($messenger, $generator, $definitionBuilder);
        $transferGenerator->execute();

        $this->assertFileExists($this->getTargetDirectory() . 'MergedDeprecatedFooBarTransfer.php');

        $this->assertSame(
            file_get_contents(__DIR__ . '/test_files/expected.merged.deprecated.transfer.php'),
            file_get_contents($this->getTargetDirectory() . 'MergedDeprecatedFooBarTransfer.php')
        );
    }

    /**
     * @return string
     */
    protected function getTargetDirectory()
    {
        return codecept_output_dir();
    }

    /**
     * @return \Symfony\Component\Console\Logger\ConsoleLogger
     */
    protected function getMessenger()
    {
        $messenger = new ConsoleLogger(new ConsoleOutput(OutputInterface::VERBOSITY_QUIET));

        return $messenger;
    }

    /**
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\GeneratorInterface
     */
    protected function getClassGenerator()
    {
        $targetDirectory = $this->getTargetDirectory();
        $generator = new ClassGenerator($targetDirectory);

        return $generator;
    }

    /**
     * @param array $sourceDirectories
     *
     * @return \Spryker\Zed\Transfer\Business\Model\Generator\DefinitionBuilderInterface
     */
    protected function getDefinitionBuilder($sourceDirectories)
    {
        $finder = new TransferDefinitionFinder($sourceDirectories);
        $normalizer = new DefinitionNormalizer();
        $loader = new TransferDefinitionLoader($finder, $normalizer);
        $definitionBuilder = new TransferDefinitionBuilder(
            $loader,
            new TransferDefinitionMerger(),
            new ClassDefinition()
        );

        return $definitionBuilder;
    }
}
