<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business\DependencyTree\Finder\PathBuilder;

use Spryker\Zed\Development\DevelopmentConfig;
use Zend\Filter\FilterChain;
use Zend\Filter\StringToLower;
use Zend\Filter\Word\CamelCaseToDash;

class SprykerMerchantPortalPathBuilder implements PathBuilderInterface
{
    /**
     * @var \Spryker\Zed\Development\DevelopmentConfig
     */
    protected $config;

    /**
     * @param \Spryker\Zed\Development\DevelopmentConfig $config
     */
    public function __construct(DevelopmentConfig $config)
    {
        $this->config = $config;
    }

    /**
     * @param string $module
     *
     * @return array
     */
    public function buildPaths(string $module): array
    {
        $filteredModule = $this->filterModule($module);

        $paths = [];
        $basePath = rtrim($this->config->getPathToInternalNamespace('SprykerMerchantPortal'), '/');
        foreach ($this->config->getApplications() as $application) {
            $paths[] = sprintf('%s/%s/src/Spryker/%s/%s', $basePath, $filteredModule, $application, $module);
            $paths[] = sprintf('%s/%s/src/Spryker/%s/%s', $basePath, $module, $application, $module);
            $paths[] = sprintf('%s/%s/tests/SprykerTest/%s/%s', $basePath, $filteredModule, $application, $module);
            $paths[] = sprintf('%s/%s/tests/SprykerTest/%s/%s', $basePath, $module, $application, $module);
        }

        return $paths;
    }

    /**
     * @param string $module
     *
     * @return string
     */
    protected function filterModule(string $module): string
    {
        if ($module === '*') {
            return $module;
        }

        $filterChain = new FilterChain();
        $filterChain
            ->attach(new CamelCaseToDash())
            ->attach(new StringToLower());

        return $filterChain->filter($module);
    }
}
