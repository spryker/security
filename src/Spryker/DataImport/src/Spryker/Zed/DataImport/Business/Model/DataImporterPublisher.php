<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\DataImport\Business\Model;

use Generated\Shared\Transfer\EventEntityTransfer;
use Spryker\Zed\Event\Business\EventFacadeInterface;

class DataImporterPublisher implements DataImporterPublisherInterface
{
    /**
     * @var \Spryker\Zed\Event\Business\EventFacadeInterface
     */
    protected $eventFacade;

    /**
     * @var array
     */
    protected static $importedEntityEvents = [];

    /**
     * TODO use bridge
     *
     * @param \Spryker\Zed\Event\Business\EventFacadeInterface $eventFacade
     */
    public function __construct(EventFacadeInterface $eventFacade)
    {
        $this->eventFacade = $eventFacade;
    }

    /**
     * @return mixed
     */
    public static function getImportedEntityEvents()
    {
        return self::$importedEntityEvents;
    }

    /**
     * @param mixed $importedEntityEvents
     *
     * @return void
     */
    public static function setImportedEntityEvents(array $importedEntityEvents)
    {
        self::$importedEntityEvents = $importedEntityEvents;
    }

    /**
     * @param array $events
     *
     * @return void
     */
    public static function addImportedEntityEvents(array $events)
    {
        $mergedArray = array_merge_recursive(static::$importedEntityEvents, $events);

        self::$importedEntityEvents = static::getUniqueArray($mergedArray);
    }

    /**
     * @return void
     */
    public function triggerEvents()
    {
        foreach (static::$importedEntityEvents as $event => $ids) {
            $uniqueIds = array_unique($ids);
            foreach ($uniqueIds as $id) {
                $this->eventFacade->trigger($event, (new EventEntityTransfer())->setId($id));
            }
        }
    }

    /**
     * @param array $mergedArray
     *
     * @return array
     */
    protected static function getUniqueArray(array $mergedArray)
    {
        $uniqueArray = [];
        foreach ($mergedArray as $event => $ids) {
            $uniqueArray[$event] = array_unique($ids);
        }

        return $uniqueArray;
    }
}
