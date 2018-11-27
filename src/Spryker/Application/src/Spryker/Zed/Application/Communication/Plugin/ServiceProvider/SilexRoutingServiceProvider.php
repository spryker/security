<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Application\Communication\Plugin\ServiceProvider;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Spryker\Shared\Application\Business\Routing\SilexRouter;
use Symfony\Cmf\Component\Routing\ChainRouter;

class SilexRoutingServiceProvider implements ServiceProviderInterface
{
    /**
     * @param \Spryker\Shared\Kernel\Communication\Application $app
     *
     * @return void
     */
    public function boot(Application $app)
    {
    }

    /**
     * @param \Spryker\Shared\Kernel\Communication\Application $app
     *
     * @return void
     */
    public function register(Application $app)
    {
        $app->extend('routers', function (ChainRouter $chainRouter) use ($app) {
            $chainRouter->add(new SilexRouter($app));

            return $chainRouter;
        });
    }
}
