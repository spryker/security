<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Currency\Plugin;

use Spryker\Yves\Kernel\AbstractPlugin;

/**
 * @method \Spryker\Yves\Currency\CurrencyFactory getFactory()
 */
class CurrencyPlugin extends AbstractPlugin implements CurrencyPluginInterface
{
    /**
     * @param string $isoCode
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function fromIsoCode($isoCode)
    {
        return $this->getFactory()->createCurrencyBuilder()->fromIsoCode($isoCode);
    }

    /**
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getCurrent()
    {
        return $this->getFactory()->createCurrencyBuilder()->getCurrent();
    }
}
