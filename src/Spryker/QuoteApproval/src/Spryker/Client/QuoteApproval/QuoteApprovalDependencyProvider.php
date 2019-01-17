<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\QuoteApproval;

use Spryker\Client\Kernel\AbstractDependencyProvider;
use Spryker\Client\Kernel\Container;
use Spryker\Client\QuoteApproval\Dependency\Client\QuoteApprovalToPermissionClientBridge;
use Spryker\Client\QuoteApproval\Dependency\Client\QuoteApprovalToZedRequestClientBridge;

class QuoteApprovalDependencyProvider extends AbstractDependencyProvider
{
    public const CLIENT_ZED_REQUEST = 'CLIENT_ZED_REQUEST';
    public const CLIENT_PERMISSION = 'CLIENT_PERMISSION';

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    public function provideServiceLayerDependencies(Container $container): Container
    {
        $container = parent::provideServiceLayerDependencies($container);
        $container = $this->addZedRequestClient($container);
        $container = $this->addPermissionClient($container);

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addZedRequestClient(Container $container): Container
    {
        $container[static::CLIENT_ZED_REQUEST] = function (Container $container) {
            return new QuoteApprovalToZedRequestClientBridge($container->getLocator()->zedRequest()->client());
        };

        return $container;
    }

    /**
     * @param \Spryker\Client\Kernel\Container $container
     *
     * @return \Spryker\Client\Kernel\Container
     */
    protected function addPermissionClient(Container $container): Container
    {
        $container[static::CLIENT_PERMISSION] = function (Container $container) {
            return new QuoteApprovalToPermissionClientBridge($container->getLocator()->permission()->client());
        };

        return $container;
    }
}
