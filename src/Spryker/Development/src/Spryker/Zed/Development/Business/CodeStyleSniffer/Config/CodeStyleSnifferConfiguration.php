<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Development\Business\CodeStyleSniffer\Config;

use InvalidArgumentException;
use Spryker\Zed\Development\DevelopmentConfig;

class CodeStyleSnifferConfiguration implements CodeStyleSnifferConfigurationInterface
{
    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_FIX
     */
    protected const OPTION_FIX = 'fix';

    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_DRY_RUN
     */
    protected const OPTION_DRY_RUN = 'dry-run';

    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_QUIET
     */
    protected const OPTION_QUIET = 'quiet';

    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_EXPLAIN
     */
    protected const OPTION_EXPLAIN = 'explain';

    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_SNIFFS
     */
    protected const OPTION_SNIFFS = 'sniffs';

    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_VERBOSE
     */
    protected const OPTION_VERBOSE = 'verbose';

    /**
     * @see \Spryker\Zed\Development\Business\CodeStyleSniffer\CodeStyleSniffer::OPTION_IGNORE
     */
    protected const OPTION_IGNORE = 'ignore';

    /**
     * @see \Spryker\Zed\Development\Communication\Console\CodeStyleSnifferConsole::OPTION_LEVEL
     */
    protected const OPTION_LEVEL = 'level';

    protected const MODULE_CONFIG_LEVEL = 'level';
    protected const LEVELS_ALLOWED = [1, 2];

    /**
     * @var \Spryker\Zed\Development\DevelopmentConfig
     */
    protected $developmentConfig;

    /**
     * @var array
     */
    protected $moduleConfig;

    /**
     * @var array
     */
    protected $configurationOptions;

    /**
     * @param \Spryker\Zed\Development\DevelopmentConfig $developmentConfig
     */
    public function __construct(DevelopmentConfig $developmentConfig)
    {
        $this->developmentConfig = $developmentConfig;
    }

    /**
     * @param array $moduleConfig
     *
     * @return $this
     */
    public function setModuleConfig(array $moduleConfig): CodeStyleSnifferConfigurationInterface
    {
        $this->moduleConfig = $moduleConfig;

        return $this;
    }

    /**
     * @param array $configurationOptions
     *
     * @return $this
     */
    public function setConfigurationOptions(array $configurationOptions): CodeStyleSnifferConfigurationInterface
    {
        $this->configurationOptions = $configurationOptions;

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     * @return string
     */
    public function getCodingStandard(): string
    {
        // TODO: make this dependent on current code sniffer level
        return $this->developmentConfig->getCodingStandard();
    }

    /**
     * {@inheritdoc}
     *
     * @return string|null
     */
    public function getIgnoredPaths(): ?string
    {
        return $this->configurationOptions[static::OPTION_IGNORE];
    }

    /**
     * {@inheritdoc}
     *
     * @return bool
     */
    public function isFixing(): bool
    {
        return $this->configurationOptions[static::OPTION_FIX];
    }

    /**
     * {@inheritdoc}
     *
     * @return bool
     */
    public function isQuiet(): bool
    {
        return $this->configurationOptions[static::OPTION_QUIET];
    }

    /**
     * {@inheritdoc}
     *
     * @return bool
     */
    public function isDryRun(): bool
    {
        return $this->configurationOptions[static::OPTION_DRY_RUN];
    }

    /**
     * {@inheritdoc}
     *
     * @return bool
     */
    public function isExplaining(): bool
    {
        return $this->configurationOptions[static::OPTION_EXPLAIN];
    }

    /**
     * {@inheritdoc}
     *
     * @return string|null
     */
    public function getSpecificSniffs(): ?string
    {
        return $this->configurationOptions[static::OPTION_SNIFFS];
    }

    /**
     * {@inheritdoc}
     *
     * @return bool
     */
    public function isVerbose(): bool
    {
        return $this->configurationOptions[static::OPTION_VERBOSE];
    }

    /**
     * {@inheritdoc}
     *
     * @throws \InvalidArgumentException
     *
     * @return int
     */
    public function getLevel(): int
    {
        $optionLevel = $this->resolveOptionLevel();

        if (!in_array($optionLevel, static::LEVELS_ALLOWED)) {
            throw new InvalidArgumentException(
                sprintf('Level should be in [%s] range', implode(', ', static::LEVELS_ALLOWED))
            );
        }

        return $optionLevel;
    }

    /**
     * @return int
     */
    protected function resolveOptionLevel(): int
    {
        $optionLevel = $this->configurationOptions[static::OPTION_LEVEL];

        if ($optionLevel !== null) {
            return (int)$optionLevel;
        }

        if (isset($this->moduleConfig[static::MODULE_CONFIG_LEVEL])) {
            return $this->moduleConfig[static::MODULE_CONFIG_LEVEL];
        }

        return $this->developmentConfig->getCodeSnifferLevel();
    }
}
