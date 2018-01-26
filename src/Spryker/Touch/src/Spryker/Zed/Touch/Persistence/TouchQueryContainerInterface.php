<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Touch\Persistence;

use DateTime;
use Generated\Shared\Transfer\LocaleTransfer;
use Spryker\Zed\Kernel\Persistence\QueryContainer\QueryContainerInterface;

interface TouchQueryContainerInterface extends QueryContainerInterface
{
    /**
     * @api
     *
     * @param string $itemType
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryTouchListByItemType($itemType);

    /**
     * @api
     *
     * @param string $itemType
     * @param string $itemId
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryTouchEntry($itemType, $itemId);

    /**
     * @api
     *
     * @param string $itemType
     * @param string $itemId
     * @param string|null $itemEvent
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryUpdateTouchEntry($itemType, $itemId, $itemEvent = null);

    /**
     * Specification:
     *  - return all items with given `$itemType` and `$itemId` whether they are active, inactive or deleted
     *
     * @api
     *
     * @param string $itemType
     * @param array $itemIds
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryTouchEntriesByItemTypeAndItemIds($itemType, array $itemIds);

    /**
     * @api
     *
     * @param string $itemType
     * @param int $idStore
     * @param int|null $idLocale
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryTouchDeleteStorageAndSearch($itemType, $idStore, $idLocale = null);

    /**
     * @api
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryExportTypes();

    /**
     * @api
     *
     * @param string $itemType
     * @param \Generated\Shared\Transfer\LocaleTransfer $locale
     * @param \DateTime $lastTouchedAt
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function createBasicExportableQuery($itemType, LocaleTransfer $locale, DateTime $lastTouchedAt);

    /**
     * @api
     *
     * @param string $itemEvent
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchQuery
     */
    public function queryTouchListByItemEvent($itemEvent);

    /**
     * @api
     *
     * @param array $touchIds
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchSearchQuery
     */
    public function queryTouchSearchByTouchIds($touchIds);

    /**
     * @api
     *
     * @param array $touchIds
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouchStorageQuery
     */
    public function queryTouchStorageByTouchIds($touchIds);
}
