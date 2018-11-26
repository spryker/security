<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerGroup\Persistence;

use Orm\Zed\Customer\Persistence\SpyCustomerQuery;
use Orm\Zed\CustomerGroup\Persistence\SpyCustomerGroupQuery;
use Orm\Zed\CustomerGroup\Persistence\SpyCustomerGroupToCustomerQuery;
use Spryker\Zed\CustomerGroup\Persistence\Propel\Mapper\CustomerGroupMapper;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;

/**
 * @method \Spryker\Zed\CustomerGroup\CustomerGroupConfig getConfig()
 * @method \Spryker\Zed\CustomerGroup\Persistence\CustomerGroupQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\CustomerGroup\Persistence\CustomerGroupRepositoryInterface getRepository()
 */
class CustomerGroupPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\CustomerGroup\Persistence\SpyCustomerGroupQuery
     */
    public function createCustomerGroupQuery()
    {
        return SpyCustomerGroupQuery::create();
    }

    /**
     * @return \Orm\Zed\CustomerGroup\Persistence\SpyCustomerGroupToCustomerQuery
     */
    public function createCustomerGroupToCustomerQuery()
    {
        return SpyCustomerGroupToCustomerQuery::create();
    }

    /**
     * @return \Orm\Zed\Customer\Persistence\SpyCustomerQuery
     */
    public function createCustomerQuery()
    {
        return SpyCustomerQuery::create();
    }

    /**
     * @return \Spryker\Zed\CustomerGroup\Persistence\Propel\Mapper\CustomerGroupMapper
     */
    public function createCustomerGroupMapper(): CustomerGroupMapper
    {
        return new CustomerGroupMapper();
    }
}
