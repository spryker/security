<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductQuantity\Persistence;

use Orm\Zed\ProductQuantity\Persistence\SpyProductQuantityQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\ProductQuantity\Persistence\Propel\Mapper\ProductQuantityMapper;
use Spryker\Zed\ProductQuantity\Persistence\Propel\Mapper\ProductQuantityMapperInterface;

/**
 * @method \Spryker\Zed\ProductQuantity\ProductQuantityConfig getConfig()
 * @method \Spryker\Zed\ProductQuantity\Persistence\ProductQuantityEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\ProductQuantity\Persistence\ProductQuantityRepositoryInterface getRepository()
 */
class ProductQuantityPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\ProductQuantity\Persistence\SpyProductQuantityQuery
     */
    public function createProductQuantityQuery(): SpyProductQuantityQuery
    {
        return SpyProductQuantityQuery::create();
    }

    /**
     * @return \Spryker\Zed\ProductQuantity\Persistence\Propel\Mapper\ProductQuantityMapperInterface
     */
    public function createProductQuantityMapper(): ProductQuantityMapperInterface
    {
        return new ProductQuantityMapper();
    }
}
