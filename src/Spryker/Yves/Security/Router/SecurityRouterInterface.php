<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security\Router;

use Spryker\Service\Container\ContainerInterface;

interface SecurityRouterInterface
{
    public function addRouter(ContainerInterface $container): void;

    public function addSecurityRoute(
        string $routeNameOrUrl,
        ?string $routeName = null
    ): void;
}
