<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Availability\Persistence;

use Orm\Zed\Availability\Persistence\SpyAvailabilityAbstractQuery;
use Orm\Zed\Availability\Persistence\SpyAvailabilityQuery;
use Spryker\Zed\Availability\AvailabilityDependencyProvider;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;

/**
 * @method \Spryker\Zed\Availability\AvailabilityConfig getConfig()
 * @method \Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface getQueryContainer()
 */
class AvailabilityPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\Availability\Persistence\SpyAvailabilityQuery
     */
    public function createSpyAvailabilityQuery()
    {
        return SpyAvailabilityQuery::create();
    }

    /**
     * @return \Orm\Zed\Availability\Persistence\SpyAvailabilityAbstractQuery
     */
    public function createSpyAvailabilityAbstractQuery()
    {
        return SpyAvailabilityAbstractQuery::create();
    }

    /**
     * @return \Spryker\Zed\Availability\Dependency\QueryContainer\AvailabilityToProductInterface
     */
    public function getProductQueryContainer()
    {
        return $this->getProvidedDependency(AvailabilityDependencyProvider::QUERY_CONTAINER_PRODUCT);
    }
}
