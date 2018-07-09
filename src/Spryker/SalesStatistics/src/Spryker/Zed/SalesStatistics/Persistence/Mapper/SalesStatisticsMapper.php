<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesStatistics\Persistence\Mapper;

use Generated\Shared\Transfer\SalesStatisticTransfer;
use Spryker\Zed\SalesStatistics\Persistence\SalesStatisticsRepository;

class SalesStatisticsMapper implements SalesStatisticsMapperInterface
{
    public const DECIMAL = 100;

    /**
     * @param array $statistic
     *
     * @return \Generated\Shared\Transfer\SalesStatisticTransfer
     */
    public function mapCountStatisticToTransfer(array $statistic): SalesStatisticTransfer
    {
        $chartDataTraceTransfer = new SalesStatisticTransfer();
        if ($statistic) {
            foreach ($statistic as $statisticItem) {
                $chartDataTraceTransfer->addLabel($statisticItem[SalesStatisticsRepository::DATE]);
                $chartDataTraceTransfer->addValue((int)$statisticItem[SalesStatisticsRepository::COUNT]);
            }
        }

        return $chartDataTraceTransfer;
    }

    /**
     * @param array $statistic
     *
     * @return \Generated\Shared\Transfer\SalesStatisticTransfer
     */
    public function mapStatusOrderStatisticToTransfer(array $statistic): SalesStatisticTransfer
    {
        $chartDataTraceTransfer = new SalesStatisticTransfer();
        if ($statistic) {
            foreach ($statistic as $statisticItem) {
                $chartDataTraceTransfer->addLabel($statisticItem[SalesStatisticsRepository::STATUS_NAME]);
                $chartDataTraceTransfer->addValue((float)$statisticItem[SalesStatisticsRepository::TOTAL] / static::DECIMAL);
            }
        }

        return $chartDataTraceTransfer;
    }

    /**
     * @param array $statistic
     *
     * @return \Generated\Shared\Transfer\SalesStatisticTransfer
     */
    public function mapTopOrderStatisticToTransfer(array $statistic): SalesStatisticTransfer
    {
        $chartDataTraceTransfer = new SalesStatisticTransfer();
        if ($statistic) {
            foreach ($statistic as $statisticItem) {
                $chartDataTraceTransfer->addLabel($statisticItem[SalesStatisticsRepository::ITEM_NAME]);
                $chartDataTraceTransfer->addValue((int)$statisticItem[SalesStatisticsRepository::COUNT]);
            }
        }

        return $chartDataTraceTransfer;
    }
}
