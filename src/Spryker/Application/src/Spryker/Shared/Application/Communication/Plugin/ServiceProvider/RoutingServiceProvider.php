<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Application\Communication\Plugin\ServiceProvider;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Symfony\Cmf\Component\Routing\ChainRouter;

/**
 * @deprecated Use Spryker\Shared\Application\ServiceProvider\RoutingServiceProvider instead
 */
class RoutingServiceProvider implements ServiceProviderInterface
{
    /**
     * {@inheritdoc}
     *
     * @param \Silex\Application $app
     *
     * @return void
     */
    public function register(Application $app)
    {
        $app['url_matcher'] = $app->share(function () use ($app) {
            /** @var \Symfony\Cmf\Component\Routing\ChainRouter $chainRouter */
            $chainRouter = $app['routers'];
            $chainRouter->setContext($app['request_context']);

            return $chainRouter;
        });

        $app['routers'] = $app->share(function () {
            return new ChainRouter();
        });
    }

    /**
     * @codeCoverageIgnore
     *
     * @param \Silex\Application $app
     *
     * @return void
     */
    public function boot(Application $app)
    {
    }
}
