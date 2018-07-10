<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductListGui\Communication\Table;

use Orm\Zed\Product\Persistence\SpyProductQuery;
use Spryker\Zed\PropelOrm\Business\Runtime\ActiveQuery\Criteria;

class AvailableProductConcreteTable extends AbstractProductConcreteTable
{
    protected const DEFAULT_URL = 'availableProductConcreteTable';
    protected const TABLE_IDENTIFIER = self::DEFAULT_URL;

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductQuery $spyProductQuery
     *
     * @return \Orm\Zed\Product\Persistence\SpyProductQuery
     */
    protected function filterQuery(SpyProductQuery $spyProductQuery): SpyProductQuery
    {
        if ($this->getIdProductList()) {
            $spyProductQuery
                ->useSpyProductListProductConcreteQuery(null, Criteria::LEFT_JOIN)
                    ->filterByFkProductList($this->getIdProductList(), Criteria::NOT_IN)
                    ->_or()
                    ->filterByFkProductList(null, Criteria::ISNULL)
                ->endUse()
                ->distinct();
        }
        return $spyProductQuery;
    }
}
