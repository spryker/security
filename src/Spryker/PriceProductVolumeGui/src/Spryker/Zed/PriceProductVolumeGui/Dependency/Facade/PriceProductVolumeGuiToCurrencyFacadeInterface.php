<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductVolumeGui\Dependency\Facade;

interface PriceProductVolumeGuiToCurrencyFacadeInterface
{
    /**
     * Specification:
     * - Returns CurrencyTransfer object for given ISO code
     *
     * @api
     *
     * @param string $isoCode
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function fromIsoCode($isoCode);
}
