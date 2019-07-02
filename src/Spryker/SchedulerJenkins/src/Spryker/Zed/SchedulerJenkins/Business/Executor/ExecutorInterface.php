<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SchedulerJenkins\Business\Executor;

use Generated\Shared\Transfer\SchedulerJenkinsResponseTransfer;
use Generated\Shared\Transfer\SchedulerJobTransfer;
use Spryker\Zed\SchedulerJenkins\Business\Api\Configuration\ConfigurationProviderInterface;

interface ExecutorInterface
{
    /**
     * @param \Spryker\Zed\SchedulerJenkins\Business\Api\Configuration\ConfigurationProviderInterface $configurationProvider
     * @param \Generated\Shared\Transfer\SchedulerJobTransfer $jobTransfer
     *
     * @return \Generated\Shared\Transfer\SchedulerJenkinsResponseTransfer
     */
    public function execute(ConfigurationProviderInterface $configurationProvider, SchedulerJobTransfer $jobTransfer): SchedulerJenkinsResponseTransfer;
}
