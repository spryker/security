<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductSchedule\Business\PriceProductSchedule;

use Generated\Shared\Transfer\PriceProductScheduleTransfer;
use Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductSchedule;

interface PriceProductScheduleMapperInterface
{
    /**
     * @param \Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductSchedule $priceProductScheduleEntity
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleTransfer
     */
    public function mapPriceProductScheduleEntityToPriceProductScheduleTransfer(SpyPriceProductSchedule $priceProductScheduleEntity): PriceProductScheduleTransfer;

    /**
     * @param \Generated\Shared\Transfer\PriceProductScheduleTransfer $priceProductScheduleTransfer
     * @param \Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductSchedule $priceProductScheduleEntity
     *
     * @return \Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductSchedule
     */
    public function mapPriceProductScheduleTransferToPriceProductScheduleEntity(PriceProductScheduleTransfer $priceProductScheduleTransfer, SpyPriceProductSchedule $priceProductScheduleEntity): SpyPriceProductSchedule;

    /**
     * @param \Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductSchedule[] $priceProductScheduleEntities
     *
     * @return \Generated\Shared\Transfer\PriceProductScheduleTransfer[]
     */
    public function mapPriceProductScheduleEntitiesToPriceProductScheduleTransfers($priceProductScheduleEntities): array;
}
