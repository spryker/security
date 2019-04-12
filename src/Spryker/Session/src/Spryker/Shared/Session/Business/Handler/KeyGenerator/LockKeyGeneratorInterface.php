<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Session\Business\Handler\KeyGenerator;

/**
 * @deprecated Use `\Spryker\Client\SessionRedisLocking\Handler\KeyGenerator\LockKeyGeneratorInterface` instead.
 */
interface LockKeyGeneratorInterface
{
    /**
     * @param string $sessionId
     *
     * @return string
     */
    public function generateLockKey($sessionId);
}
