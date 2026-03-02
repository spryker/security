<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security\Configurator;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\SecurityExtension\Configuration\SecurityConfigurationInterface;

interface SecurityConfiguratorInterface
{
    public function getSecurityConfiguration(ContainerInterface $container): SecurityConfigurationInterface;
}
