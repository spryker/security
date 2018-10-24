<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOption\Persistence;

use Orm\Zed\ProductOption\Persistence\Map\SpyProductAbstractProductOptionGroupTableMap;
use Propel\Runtime\ActiveQuery\Criteria;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;

/**
 * @method \Spryker\Zed\ProductOption\Persistence\ProductOptionPersistenceFactory getFactory()
 */
class ProductOptionRepository extends AbstractRepository implements ProductOptionRepositoryInterface
{
    /**
     * @param int $idProductOptionGroup
     * @param bool $currentIsActiveState
     *
     * @return int[]
     */
    public function findProductAbstractWithDifferentStateIdIndexes(int $idProductOptionGroup, bool $currentIsActiveState): array
    {
        $productOptionGroupProductAbstractIdIndexes = $this->getFactory()
            ->createProductOptionGroupQuery()
            ->filterByIdProductOptionGroup($idProductOptionGroup)
            ->filterByActive($currentIsActiveState, Criteria::NOT_EQUAL)
            ->joinWithSpyProductAbstractProductOptionGroup()
            ->select(SpyProductAbstractProductOptionGroupTableMap::COL_FK_PRODUCT_ABSTRACT)
            ->find()
            ->toArray();

        return $productOptionGroupProductAbstractIdIndexes;
    }
}
