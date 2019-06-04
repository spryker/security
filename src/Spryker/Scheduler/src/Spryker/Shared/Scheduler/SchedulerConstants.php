<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Scheduler;

/**
 * Declares global environment configuration keys. Do not use it for other class constants.
 */
interface SchedulerConstants
{
    /**
     * Specification:
     * - Defines the set of scheduler IDs to be enabled.
     *
     * @api
     */
    public const ENABLED_SCHEDULERS = 'SCHEDULER:JENKINS_CONFIGURATION';
}
