<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Price\Business\Model;

use Generated\Shared\Transfer\PriceProductTransfer;

interface BulkWriterInterface
{
    /**
     * @param string $name
     *
     * @throws \Exception
     * @throws \Propel\Runtime\Exception\PropelException
     *
     * @return \Orm\Zed\Price\Persistence\SpyPriceType
     */
    public function createPriceType($name);

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $priceProductTransfer
     *
     * @return void
     */
    public function setPriceForProduct(PriceProductTransfer $priceProductTransfer);

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $transferPriceProduct
     *
     * @return \Orm\Zed\Price\Persistence\SpyPriceProduct
     */
    public function createPriceForProduct(PriceProductTransfer $transferPriceProduct);

    /**
     * @return void
     */
    public function flush();
}
