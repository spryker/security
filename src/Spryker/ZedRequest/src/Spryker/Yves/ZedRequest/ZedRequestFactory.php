<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\ZedRequest;

use Spryker\Shared\ZedRequest\Client\HandlerStack\HandlerStackContainer;
use Spryker\Yves\Kernel\AbstractFactory;
use Spryker\Yves\ZedRequest\Plugin\ZedRequestHeaderMiddleware;
use Spryker\Yves\ZedRequest\Plugin\ZedRequestLogPlugin;
use Spryker\Yves\ZedRequest\Plugin\ZedResponseLogPlugin;

class ZedRequestFactory extends AbstractFactory
{
    /**
     * @return \Spryker\Shared\ZedRequest\Client\HandlerStack\HandlerStackContainer
     */
    public function createHandlerStackContainer()
    {
        return new HandlerStackContainer();
    }

    /**
     * @return \Spryker\Yves\ZedRequest\Plugin\ZedRequestLogPlugin|\Spryker\Shared\ZedRequest\Client\Middleware\MiddlewareInterface
     */
    public function createRequestLogPlugin()
    {
        return new ZedRequestLogPlugin();
    }

    /**
     * @return \Spryker\Yves\ZedRequest\Plugin\ZedResponseLogPlugin|\Spryker\Shared\ZedRequest\Client\Middleware\MiddlewareInterface
     */
    public function createResponseLogPlugin()
    {
        return new ZedResponseLogPlugin();
    }

    /**
     * @return \Spryker\Yves\ZedRequest\Plugin\ZedRequestHeaderMiddleware
     */
    public function createZedRequestHeaderMiddleware()
    {
        return new ZedRequestHeaderMiddleware($this->getUtilNetworkService());
    }

    /**
     * @return \Spryker\Yves\ZedRequest\Dependency\Service\ZedRequestToUtilNetworkInterface
     */
    protected function getUtilNetworkService()
    {
        return $this->getProvidedDependency(ZedRequestDependencyProvider::SERVICE_UTIL_NETWORK);
    }
}
