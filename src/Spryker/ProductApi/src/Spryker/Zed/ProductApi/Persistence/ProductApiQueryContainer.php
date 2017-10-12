<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductApi\Persistence;

use Spryker\Zed\Kernel\Persistence\AbstractQueryContainer;

/**
 * @method \Spryker\Zed\ProductApi\Persistence\ProductApiPersistenceFactory getFactory()
 */
class ProductApiQueryContainer extends AbstractQueryContainer implements ProductApiQueryContainerInterface
{
    /**
     * @api
     *
     * @return \Orm\Zed\Product\Persistence\SpyProductAbstractQuery
     */
    public function queryFind()
    {
        return $this->getFactory()->createProductAbstractQuery();
    }

    /**
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return null|\Orm\Zed\Product\Persistence\SpyProductAbstractQuery
     */
    public function queryGet($idProductAbstract)
    {
        $query = $this->getFactory()->createProductAbstractQuery();

        return $query->filterByIdProductAbstract($idProductAbstract);
    }

    /**
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return null|\Orm\Zed\Product\Persistence\SpyProductAbstractQuery
     */
    public function queryRemove($idProductAbstract)
    {
        $query = $this->getFactory()->createProductAbstractQuery();

        return $query->filterByIdProductAbstract($idProductAbstract);
    }
}
