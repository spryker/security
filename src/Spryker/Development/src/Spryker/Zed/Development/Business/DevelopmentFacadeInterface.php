<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business;

use Generated\Shared\Transfer\ComposerJsonValidationRequestTransfer;
use Generated\Shared\Transfer\ComposerJsonValidationResponseTransfer;
use Generated\Shared\Transfer\DependencyCollectionTransfer;
use Generated\Shared\Transfer\DependencyProviderCollectionTransfer;
use Generated\Shared\Transfer\DependencyValidationRequestTransfer;
use Generated\Shared\Transfer\DependencyValidationResponseTransfer;
use Generated\Shared\Transfer\ModuleFilterTransfer;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

interface DevelopmentFacadeInterface
{
    /**
     * @api
     *
     * @param string|null $module
     * @param array $options
     *
     * @return int Exit code
     */
    public function checkCodeStyle($module = null, array $options = []);

    /**
     * @api
     *
     * @param string|null $module
     * @param array $options
     *
     * @return void
     */
    public function runTest($module, array $options = []);

    /**
     * @api
     *
     * @param string|null $module
     * @param array $options
     *
     * @return int Exit code
     */
    public function runPhpMd($module, array $options = []);

    /**
     * @api
     *
     * @param string $module
     * @param string $toModule
     * @param array $methods
     *
     * @return void
     */
    public function createBridge($module, $toModule, array $methods);

    /**
     * @api
     *
     * @param string $module
     * @param array $options
     *
     * @return void
     */
    public function createModule($module, array $options);

    /**
     * Specification:
     * - Parses all dependencies for a given module.
     *
     * @api
     *
     * @param string $module
     * @param string|null $dependencyType
     *
     * @return \Generated\Shared\Transfer\DependencyCollectionTransfer
     */
    public function showOutgoingDependenciesForModule(string $module, ?string $dependencyType = null): DependencyCollectionTransfer;

    /**
     * @api
     *
     * @param string $moduleName
     *
     * @return array
     */
    public function showIncomingDependenciesForModule($moduleName);

    /**
     * @api
     *
     * @deprecated Please use `getModules()` instead.
     *
     * @return array
     */
    public function getAllModules();

    /**
     * @api
     *
     * @deprecated Use `getAllModules()` instead.
     *
     * @return array
     */
    public function getAllBundles();

    /**
     * Specification:
     * - Builds the dependency tree for all modules if * is used as $module.
     * - Builds the dependency tree for specific module if $module is name of a module.
     *
     * @api
     *
     * @param string $module
     *
     * @return void
     */
    public function buildDependencyTree(string $module);

    /**
     * Specification:
     * - Calculates the stability of each module.

     * @api
     *
     * @return array
     */
    public function calculateStability();

    /**
     * @api
     *
     * @param string|bool $moduleToView
     * @param array $excludedModules
     * @param bool $showIncomingDependencies
     *
     * @return string
     */
    public function drawOutgoingDependencyTreeGraph($moduleToView, array $excludedModules = [], $showIncomingDependencies = false);

    /**
     * @api
     *
     * @param string|bool $moduleToView
     *
     * @return string
     */
    public function drawDetailedDependencyTreeGraph($moduleToView);

    /**
     * @api
     *
     * @param bool $showEngineModule
     * @param string|bool $moduleToView
     *
     * @return string
     */
    public function drawSimpleDependencyTreeGraph($showEngineModule, $moduleToView);

    /**
     * @api
     *
     * @param string $moduleToView
     *
     * @return string
     */
    public function drawExternalDependencyTreeGraph($moduleToView);

    /**
     * @api
     *
     * @return bool
     */
    public function getAdjacencyMatrixData();

    /**
     * @api
     *
     * @return array
     */
    public function getDependencyViolations();

    /**
     * @api
     *
     * @return array
     */
    public function getEngineModuleList();

    /**
     * @api
     *
     * @param array $modules
     * @param bool $dryRun
     *
     * @return array
     */
    public function updateComposerJsonInModules(array $modules, $dryRun = false);

    /**
     * @api
     *
     * @return array
     */
    public function getExternalDependencyTree();

    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\DependencyCollectionTransfer $dependencyCollectionTransfer
     *
     * @return array
     */
    public function getComposerDependencyComparison(DependencyCollectionTransfer $dependencyCollectionTransfer);

    /**
     * @api
     *
     * @return void
     */
    public function generateYvesIdeAutoCompletion();

    /**
     * @api
     *
     * @return void
     */
    public function generateZedIdeAutoCompletion();

    /**
     * @api
     *
     * @return void
     */
    public function generateClientIdeAutoCompletion();

    /**
     * @api
     *
     * @return void
     */
    public function generateServiceIdeAutoCompletion();

    /**
     * @api
     *
     * @return void
     */
    public function generateGlueIdeAutoCompletion();

    /**
     * Run the architecture sniffer against the given module and returns the violations
     *
     * @api
     *
     * @param string $directory
     * @param array $options
     *
     * @return array
     */
    public function runArchitectureSniffer($directory, array $options = []);

    /**
     * Returns a list of all modules in project and core namespaces
     *
     * @api
     *
     * @return array
     */
    public function listAllModules();

    /**
     * @api
     *
     * @deprecated Use `listAllModules` instead.
     *
     * @return array
     */
    public function listAllBundles();

    /**
     * Returns all architecture rules
     *
     * @api
     *
     * @return array
     */
    public function getArchitectureRules();

    /**
     * Specification:
     * - Runs PHPStan static code analyzing tool.
     *
     * @api
     *
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    public function runPhpstan(InputInterface $input, OutputInterface $output);

    /**
     * Specification:
     * - Validates that Abstract classes for database table exist.
     *
     * @api
     *
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     * @param string|null $module
     *
     * @return bool
     */
    public function runPropelAbstractValidation(OutputInterface $output, ?string $module): bool;

    /**
     * Specification:
     * - Parses all dependencies in src and tests directory of a given module.
     * - Parses all defined composer dependencies.
     * - Compares and validates the parsed results.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\DependencyValidationRequestTransfer $dependencyValidationRequestTransfer
     *
     * @return \Generated\Shared\Transfer\DependencyValidationResponseTransfer
     */
    public function validateModuleDependencies(DependencyValidationRequestTransfer $dependencyValidationRequestTransfer): DependencyValidationResponseTransfer;

    /**
     * Specification:
     * - Validates composer.json file for given module.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ComposerJsonValidationRequestTransfer $composerJsonValidationRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ComposerJsonValidationResponseTransfer
     */
    public function validateComposerJson(ComposerJsonValidationRequestTransfer $composerJsonValidationRequestTransfer): ComposerJsonValidationResponseTransfer;

    /**
     * Specification:
     * - Returns a collection of all Plugins used inside projects DependencyProvider.
     * - Parses use statements of project dependency provider.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ModuleFilterTransfer|null $moduleFilterTransfer
     *
     * @return \Generated\Shared\Transfer\DependencyProviderCollectionTransfer
     */
    public function getInProjectDependencyProviderUsedPlugins(?ModuleFilterTransfer $moduleFilterTransfer = null): DependencyProviderCollectionTransfer;

    /**
     * Specification:
     * - Finds all project modules.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ModuleFilterTransfer|null $moduleFilterTransfer
     *
     * @return \Generated\Shared\Transfer\ModuleTransfer[]
     */
    public function findProjectModules(?ModuleFilterTransfer $moduleFilterTransfer = null): array;

    /**
     * Specification:
     * - Loads all modules in all added module directories.
     * - Creates an array of ModuleTransfer objects.
     * - ModuleTransfer objects also contain an OrganizationTransfer object.
     * - The key of the returned array is `OrganizationName.ModuleName`.
     *
     * @api
     *
     * @return array
     */
    public function getModules();

    /**
     * Specification:
     * - Find all modules.
     * - Creates an array of ModuleTransfer objects.
     * - The key of the returned array is `OrganizationName.ModuleName`.
     * - A ModuleFilterTransfer can be used to filter the returned collection.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ModuleFilterTransfer|null $moduleFilterTransfer
     *
     * @return \Generated\Shared\Transfer\ModuleTransfer[]
     */
    public function findModules(?ModuleFilterTransfer $moduleFilterTransfer = null): array;

    /**
     * Specification:
     * - Returns a list of packages defined in the Spryker namespace.
     * - Packages are not spryker modules.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\PackageTransfer[]
     */
    public function findPackages(): array;
}
