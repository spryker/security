<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Collector\Business\Collector\Storage;

use Generated\Shared\Transfer\LocaleTransfer;
use Orm\Zed\Touch\Persistence\Map\SpyTouchStorageTableMap;
use Orm\Zed\Touch\Persistence\Map\SpyTouchTableMap;
use Orm\Zed\Touch\Persistence\SpyTouchQuery;
use Propel\Runtime\ActiveQuery\Criteria;
use Propel\Runtime\ActiveQuery\Join;
use Spryker\Zed\Collector\Business\Collector\AbstractPropelCollector;
use Spryker\Zed\Collector\CollectorConfig;

abstract class AbstractStoragePropelCollector extends AbstractPropelCollector
{
    /**
     * @var \Spryker\Zed\Collector\CollectorConfig|null
     */
    protected $config = null;

    /**
     * @param \Orm\Zed\Touch\Persistence\SpyTouchQuery $touchQuery
     * @param \Generated\Shared\Transfer\LocaleTransfer $locale
     *
     * @return void
     */
    protected function prepareCollectorScope(SpyTouchQuery $touchQuery, LocaleTransfer $locale)
    {
        if ($this->isStorageTableJoinWithLocaleEnabled()) {
            $this->joinStorageTableWithLocale($touchQuery, $locale);
        } else {
            $this->joinStorageTable($touchQuery);
        }

        $touchQuery->withColumn(SpyTouchStorageTableMap::COL_ID_TOUCH_STORAGE, CollectorConfig::COLLECTOR_STORAGE_KEY);

        parent::prepareCollectorScope($touchQuery, $locale);
    }

    /**
     * @return bool
     */
    protected function isStorageTableJoinWithLocaleEnabled()
    {
        return ($this->config && $this->config->getEnablePrepareScopeKeyJoinFixFeatureFlag() === true);
    }

    /**
     * @param \Orm\Zed\Touch\Persistence\SpyTouchQuery $touchQuery
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @return void
     */
    protected function joinStorageTableWithLocale(SpyTouchQuery $touchQuery, LocaleTransfer $localeTransfer)
    {
        $storageJoin = new Join(
            SpyTouchTableMap::COL_ID_TOUCH,
            SpyTouchStorageTableMap::COL_FK_TOUCH,
            Criteria::LEFT_JOIN
        );
        $touchQuery->addJoinObject($storageJoin, 'storageJoin');
        $touchQuery->addJoinCondition(
            'storageJoin',
            sprintf(
                '%s = %s',
                SpyTouchStorageTableMap::COL_FK_LOCALE,
                (int)$localeTransfer->requireIdLocale()->getIdLocale()
            )
        );
    }

    /**
     * @param \Orm\Zed\Touch\Persistence\SpyTouchQuery $touchQuery
     *
     * @return void
     */
    protected function joinStorageTable(SpyTouchQuery $touchQuery)
    {
        $touchQuery->addJoin(
            SpyTouchTableMap::COL_ID_TOUCH,
            SpyTouchStorageTableMap::COL_FK_TOUCH,
            Criteria::LEFT_JOIN
        );
    }

    /**
     * @param \Spryker\Zed\Collector\CollectorConfig $config
     *
     * @return void
     */
    public function setConfig(CollectorConfig $config)
    {
        $this->config = $config;
    }
}
