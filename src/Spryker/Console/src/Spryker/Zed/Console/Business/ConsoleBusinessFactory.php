<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Console\Business;

use Spryker\Zed\Console\Business\Model\ConsoleRunnerHook;
use Spryker\Zed\Console\ConsoleDependencyProvider;
use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;

/**
 * @method \Spryker\Zed\Console\ConsoleConfig getConfig()
 */
class ConsoleBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\Console\Business\Model\ConsoleRunnerHookInterface
     */
    public function createConsoleRunnerHook()
    {
        return new ConsoleRunnerHook(
            $this->getPreRunHookPlugins(),
            $this->getPostRunHookPlugins()
        );
    }

    /**
     * @return \Symfony\Component\Console\Command\Command[]
     */
    public function getConsoleCommands()
    {
        return $this->getProvidedDependency(ConsoleDependencyProvider::COMMANDS);
    }

    /**
     * @return \Symfony\Component\EventDispatcher\EventSubscriberInterface[]
     */
    public function getEventSubscriber()
    {
        return $this->getProvidedDependency(ConsoleDependencyProvider::EVENT_SUBSCRIBER);
    }

    /**
     * @return \Silex\ServiceProviderInterface[]
     */
    public function getServiceProviders()
    {
        return $this->getProvidedDependency(ConsoleDependencyProvider::SERVICE_PROVIDERS);
    }

    /**
     * @return \Spryker\Zed\Console\Dependency\Plugin\ConsolePreRunHookPluginInterface[]
     */
    public function getPreRunHookPlugins()
    {
        return $this->getProvidedDependency(ConsoleDependencyProvider::PLUGINS_CONSOLE_PRE_RUN_HOOK);
    }

    /**
     * @return \Spryker\Zed\Console\Dependency\Plugin\ConsolePostRunHookPluginInterface[]
     */
    public function getPostRunHookPlugins()
    {
        return $this->getProvidedDependency(ConsoleDependencyProvider::PLUGINS_CONSOLE_POST_RUN_HOOK);
    }
}
