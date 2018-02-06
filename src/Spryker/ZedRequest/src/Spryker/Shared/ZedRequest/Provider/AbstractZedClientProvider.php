<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\ZedRequest\Provider;

use Spryker\Client\ZedRequest\Client\HttpClient;
use Spryker\Client\ZedRequest\Client\ZedClient;
use Spryker\Shared\Config\Config;
use Spryker\Shared\Kernel\AbstractClientProvider;
use Spryker\Shared\ZedRequest\ZedRequestConstants;

/**
 * @deprecated Will be removed in the next major version. Please use ZedRequestFactory.
 *
 * @method \Spryker\Shared\ZedRequest\Client\AbstractZedClientInterface getInstance()
 */
abstract class AbstractZedClientProvider extends AbstractClientProvider
{
    /**
     * @deprecated Will be removed in the next major version. Please use ZedRequestFactory->createClient().
     *
     * @return \Spryker\Shared\ZedRequest\Client\AbstractZedClient
     */
    protected function createZedClient()
    {
        $httpClient = new HttpClient(
            $this->getBaseUrl(),
            Config::get(ZedRequestConstants::TRANSFER_USERNAME),
            Config::get(ZedRequestConstants::TRANSFER_PASSWORD)
        );

        return new ZedClient($httpClient);
    }

    /**
     * @return string
     */
    protected function getBaseUrl()
    {
        if (!Config::hasKey(ZedRequestConstants::BASE_URL_ZED_API)) {
            return 'http://' . Config::get(ZedRequestConstants::HOST_ZED_API);
        }

        return Config::get(ZedRequestConstants::BASE_URL_ZED_API);
    }
}
