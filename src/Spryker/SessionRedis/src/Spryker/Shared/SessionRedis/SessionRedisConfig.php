<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\SessionRedis;

use Spryker\Shared\Kernel\AbstractSharedConfig;

class SessionRedisConfig extends AbstractSharedConfig
{
    protected const SESSION_HANDLER_REDIS_NAME = 'redis';
    protected const SESSION_HANDLER_REDIS_LOCKING_NAME = 'redis_locking';

    protected const DEFAULT_REDIS_DATABASE = 0;

    /**
     * @return string
     */
    public function getSessionHandlerRedisName(): string
    {
        return static::SESSION_HANDLER_REDIS_NAME;
    }

    /**
     * @return string
     */
    public function getSessionHandlerRedisLockingName(): string
    {
        return static::SESSION_HANDLER_REDIS_LOCKING_NAME;
    }

    /**
     * @return string
     */
    public function getDefaultRedisDatabase(): string
    {
        return static::DEFAULT_REDIS_DATABASE;
    }

    /**
     * @return int
     */
    public function getLockingTimeoutInMilliseconds(): int
    {
        return $this->get(SessionRedisConstants::LOCKING_TIMEOUT_MILLISECONDS, 0);
    }

    /**
     * @return int
     */
    public function getLockingRetryDelayInMicroseconds(): int
    {
        return $this->get(SessionRedisConstants::LOCKING_RETRY_DELAY_MICROSECONDS, 0);
    }

    /**
     * @return int
     */
    public function getLockingLockTtlInMilliseconds(): int
    {
        return $this->get(SessionRedisConstants::LOCKING_LOCK_TTL_MILLISECONDS, 0);
    }
}
