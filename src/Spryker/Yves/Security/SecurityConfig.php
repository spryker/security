<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security;

use Spryker\Shared\Security\SecurityConstants;
use Spryker\Yves\Kernel\AbstractBundleConfig;

class SecurityConfig extends AbstractBundleConfig
{
    /**
     * @var int
     */
    protected const BCRYPT_FACTOR = 12;

    /**
     * @var int
     */
    protected const DEFAULT_REQUEST_HTTP_PORT = 80;

    /**
     * @var int
     */
    protected const DEFAULT_REQUEST_HTTPS_PORT = 443;

    /**
     * @api
     *
     * @return int
     */
    public function getHttpPort(): int
    {
        return $this->get(SecurityConstants::YVES_HTTP_PORT, static::DEFAULT_REQUEST_HTTP_PORT);
    }

    /**
     * @api
     *
     * @return int
     */
    public function getHttpsPort(): int
    {
        return $this->get(SecurityConstants::YVES_HTTPS_PORT, static::DEFAULT_REQUEST_HTTPS_PORT);
    }

    /**
     * @api
     *
     * @return bool
     */
    public function hideUserNotFoundException(): bool
    {
        return true;
    }

    /**
     * @api
     *
     * @return int
     */
    public function getBCryptCost(): int
    {
        return static::BCRYPT_FACTOR;
    }
}
