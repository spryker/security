<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Currency\Communication\Plugin;

/**
 * @method \Spryker\Zed\Currency\Business\CurrencyFacadeInterface getFacade()
 */
interface CurrencyPluginInterface
{
    /**
     * @param string $isoCode
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function fromIsoCode($isoCode);

    /**
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getCurrent();
}
