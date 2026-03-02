<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Security\Communication\Loader;

use Spryker\Service\Container\ContainerInterface;

interface ServicesLoaderInterface
{
    public function provide(ContainerInterface $container): ContainerInterface;
}
