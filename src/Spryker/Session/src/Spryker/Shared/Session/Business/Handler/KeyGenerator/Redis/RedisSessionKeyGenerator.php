<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Session\Business\Handler\KeyGenerator\Redis;

use Spryker\Shared\Session\Business\Handler\KeyGenerator\SessionKeyGeneratorInterface;

class RedisSessionKeyGenerator implements SessionKeyGeneratorInterface
{
    const KEY_PREFIX = 'session:';

    /**
     * @param string $sessionId
     *
     * @return string
     */
    public function generateSessionKey($sessionId)
    {
        return static::KEY_PREFIX . $sessionId;
    }
}
