<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\UrlStorage;

use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\UrlStorage\UrlStorageFactory getFactory()
 */
class UrlStorageClient extends AbstractClient implements UrlStorageClientInterface
{
    /**
     * @api
     *
     * @param string $url
     * @param string $localeName
     *
     * @return array
     */
    public function matchUrl($url, $localeName)
    {
        return $this
            ->getFactory()
            ->createUrlStorageReader()
            ->matchUrl($url, $localeName);
    }

    /**
     * @api
     *
     * @param string $url
     *
     * @return array
     */
    public function getUrlData($url)
    {
        return $this
            ->getFactory()
            ->createUrlStorageReader()
            ->getUrlData($url);
    }
}
