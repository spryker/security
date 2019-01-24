<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Application;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\ApplicationExtension\Dependency\Plugin\ApplicationPluginInterface;
use Spryker\Shared\ApplicationExtension\Dependency\Plugin\BootableApplicationPluginInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernel;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\TerminableInterface;

class Application implements HttpKernelInterface, TerminableInterface
{
    /**
     * @var \Spryker\Shared\ApplicationExtension\Dependency\Plugin\ApplicationPluginInterface[]
     */
    protected $plugins = [];

    /**
     * @var \Spryker\Shared\ApplicationExtension\Dependency\Plugin\BootableApplicationPluginInterface[]
     */
    protected $bootablePlugins = [];

    /**
     * @var \Spryker\Service\Container\ContainerInterface
     */
    protected $container;

    /**
     * @var bool
     */
    protected $booted = false;

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     */
    public function __construct(ContainerInterface $container)
    {
        $this->container = $container;
    }

    /**
     * @param \Spryker\Shared\ApplicationExtension\Dependency\Plugin\ApplicationPluginInterface $applicationPlugin
     *
     * @return $this
     */
    public function registerApplicationPlugin(ApplicationPluginInterface $applicationPlugin)
    {
        $this->plugins[] = $applicationPlugin;
        $this->container = $applicationPlugin->provide($this->container);

        if ($applicationPlugin instanceof BootableApplicationPluginInterface) {
            $this->bootablePlugins[] = $applicationPlugin;
        }

        return $this;
    }

    /**
     * @return $this
     */
    public function boot()
    {
        if (!$this->booted) {
            $this->booted = true;
            $this->bootPlugins();
        }

        return $this;
    }

    /**
     * @return void
     */
    public function run(): void
    {
        $request = Request::createFromGlobals();

        $this->container->set('request', $request);

        $response = $this->handle($request);
        $response->send();
        $this->terminate($request, $response);
    }

    /**
     * @internal Don't use this method unless you know why.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param int $type
     * @param bool $catch
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = true): Response
    {
        $response = $this->getKernel()->handle($request);

        return $response;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Symfony\Component\HttpFoundation\Response $response
     *
     * @return void
     */
    public function terminate(Request $request, Response $response): void
    {
        $this->getKernel()->terminate($request, $response);
    }

    /**
     * @return void
     */
    protected function bootPlugins(): void
    {
        foreach ($this->bootablePlugins as $bootablePlugin) {
            $this->container = $bootablePlugin->boot($this->container);
        }
    }

    /**
     * @return \Symfony\Component\HttpKernel\HttpKernel
     */
    protected function getKernel(): HttpKernel
    {
        return $this->container->get('kernel');
    }
}
