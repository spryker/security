<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Storage\Dependency\Client;

interface StorageToStoreClientInterface
{
    /**
     * @return string
     */
    public function getStoreName(): string;

    /**
     * @return string
     */
    public function getCurrentLocale(): string;
}
