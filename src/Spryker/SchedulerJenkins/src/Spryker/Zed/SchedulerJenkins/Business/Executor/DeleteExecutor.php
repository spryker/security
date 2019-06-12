<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SchedulerJenkins\Business\Executor;

use Generated\Shared\Transfer\SchedulerJenkinsResponseTransfer;
use Generated\Shared\Transfer\SchedulerJobTransfer;
use Spryker\Zed\SchedulerJenkins\Business\Api\JenkinsApiInterface;

class DeleteExecutor implements ExecutorInterface
{
    protected const DELETE_JOB_URL_TEMPLATE = 'job/%s/doDelete';

    /**
     * @var \Spryker\Zed\SchedulerJenkins\Business\Api\JenkinsApiInterface
     */
    protected $jenkinsApi;

    /**
     * @param \Spryker\Zed\SchedulerJenkins\Business\Api\JenkinsApiInterface $jenkinsApi
     */
    public function __construct(
        JenkinsApiInterface $jenkinsApi
    ) {
        $this->jenkinsApi = $jenkinsApi;
    }

    /**
     * @param string $idScheduler
     * @param \Generated\Shared\Transfer\SchedulerJobTransfer $jobTransfer
     *
     * @return \Generated\Shared\Transfer\SchedulerJenkinsResponseTransfer
     */
    public function execute(string $idScheduler, SchedulerJobTransfer $jobTransfer): SchedulerJenkinsResponseTransfer
    {
        $jobTransfer->requireName();

        return $this->jenkinsApi->executePostRequest(
            $idScheduler,
            sprintf(static::DELETE_JOB_URL_TEMPLATE, $jobTransfer->getName())
        );
    }
}
