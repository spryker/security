<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceDataFeed\Persistence;

use Generated\Shared\Transfer\PriceDataFeedTransfer;
use Spryker\Zed\Kernel\Persistence\QueryContainer\QueryContainerInterface;

interface PriceDataFeedQueryContainerInterface extends QueryContainerInterface
{
    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\PriceDataFeedTransfer|null $priceDataFeedTransfer
     *
     * @return \Spryker\Zed\Price\Persistence\PriceQueryContainerInterface
     */
    public function queryPriceDataFeed(PriceDataFeedTransfer $priceDataFeedTransfer = null);
}
