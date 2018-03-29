<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DataImport\Business\Model\DataImportStep;

use Spryker\Zed\DataImport\Business\Model\DataImporterPublisher;

/**
 * @SuppressWarnings(PHPMD.NumberOfChildren)
 */
class PublishAwareStep implements DataImportStepAfterExecuteInterface
{
    /**
     * @var array
     */
    protected $entityEvents = [];

    /**
     * @return void
     */
    public function afterExecute()
    {
        DataImporterPublisher::addImportedEntityEvents($this->entityEvents);
    }

    /**
     * @param string $eventName
     * @param int $entityId
     *
     * @return void
     */
    public function addPublishEvents($eventName, $entityId)
    {
        $this->entityEvents[$eventName][] = $entityId;
    }
}
