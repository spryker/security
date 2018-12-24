<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamation\Persistence;

use Orm\Zed\Sales\Persistence\SpySalesOrderQuery;
use Orm\Zed\SalesReclamation\Persistence\SpySalesReclamationItemQuery;
use Orm\Zed\SalesReclamation\Persistence\SpySalesReclamationQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\SalesReclamation\Persistence\Propel\Mapper\SalesReclamationMapper;
use Spryker\Zed\SalesReclamation\Persistence\Propel\Mapper\SalesReclamationMapperInterface;

/**
 * @method \Spryker\Zed\SalesReclamation\SalesReclamationConfig getConfig()
 * @method \Spryker\Zed\SalesReclamation\Persistence\SalesReclamationQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\SalesReclamation\Persistence\SalesReclamationEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\SalesReclamation\Persistence\SalesReclamationRepositoryInterface getRepository()
 */
class SalesReclamationPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\SalesReclamation\Persistence\SpySalesReclamationQuery
     */
    public function createSalesReclamationQuery(): SpySalesReclamationQuery
    {
        return SpySalesReclamationQuery::create();
    }

    /**
     * @return \Orm\Zed\SalesReclamation\Persistence\SpySalesReclamationItemQuery
     */
    public function createSalesReclamationItemQuery(): SpySalesReclamationItemQuery
    {
        return SpySalesReclamationItemQuery::create();
    }

    /**
     * @return \Orm\Zed\Sales\Persistence\SpySalesOrderQuery
     */
    public function createSalesOrderQuery(): SpySalesOrderQuery
    {
        return SpySalesOrderQuery::create();
    }

    /**
     * @return \Spryker\Zed\SalesReclamation\Persistence\Propel\Mapper\SalesReclamationMapperInterface
     */
    public function createSalesReclamationMapper(): SalesReclamationMapperInterface
    {
        return new SalesReclamationMapper();
    }
}
