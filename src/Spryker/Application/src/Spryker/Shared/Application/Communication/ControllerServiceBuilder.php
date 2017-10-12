<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Application\Communication;

use Pimple;
use Spryker\Shared\Kernel\ClassResolver\Controller\AbstractControllerResolver;
use Spryker\Shared\Kernel\Communication\BundleControllerActionInterface;
use Spryker\Shared\Kernel\Communication\RouteNameResolverInterface;

class ControllerServiceBuilder
{
    /**
     * @param \Pimple $application
     * @param \Spryker\Shared\Kernel\Communication\BundleControllerActionInterface $bundleControllerAction
     * @param \Spryker\Shared\Kernel\ClassResolver\Controller\AbstractControllerResolver $controllerResolver
     * @param \Spryker\Shared\Kernel\Communication\RouteNameResolverInterface $routeNameResolver
     *
     * @return string
     */
    public function createServiceForController(
        Pimple $application,
        BundleControllerActionInterface $bundleControllerAction,
        AbstractControllerResolver $controllerResolver,
        RouteNameResolverInterface $routeNameResolver
    ) {
        $serviceName = 'controller.service.' . str_replace('/', '.', $routeNameResolver->resolve());
        $service = function () use ($application, $controllerResolver, $bundleControllerAction) {
            $controller = $controllerResolver->resolve($bundleControllerAction);
            $controller->setApplication($application);
            $controller->initialize();

            return $controller;
        };

        $application[$serviceName] = $application->share($service);

        return $serviceName . ':' . $bundleControllerAction->getAction() . 'Action';
    }
}
