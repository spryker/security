<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Currency\Persistence;

use Orm\Zed\Currency\Persistence\SpyCurrencyQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;

/**
 * @method \Spryker\Zed\Currency\CurrencyConfig getConfig()
 * @method \Spryker\Zed\Currency\Persistence\CurrencyQueryContainer getQueryContainer()
 */
class CurrencyPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\Currency\Persistence\SpyCurrencyQuery
     */
    public function createCurrencyQuery()
    {
        return SpyCurrencyQuery::create();
    }
}
