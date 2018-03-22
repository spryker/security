<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Money\Formatter\IntlMoneyFormatter;

use NumberFormatter;

class IntlMoneyFormatterWithCurrency extends AbstractIntlMoneyFormatter
{
    /**
     * @param string $localeName
     *
     * @return \NumberFormatter
     */
    protected function getNumberFormatter($localeName)
    {
        $numberFormatter = new NumberFormatter($localeName, NumberFormatter::CURRENCY);

        return $numberFormatter;
    }
}
