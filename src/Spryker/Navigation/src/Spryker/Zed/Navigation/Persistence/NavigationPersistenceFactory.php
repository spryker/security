<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Navigation\Persistence;

use Orm\Zed\Navigation\Persistence\Base\SpyNavigationQuery;
use Orm\Zed\Navigation\Persistence\SpyNavigationNodeLocalizedAttributesQuery;
use Orm\Zed\Navigation\Persistence\SpyNavigationNodeQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;

/**
 * @method \Spryker\Zed\Navigation\Persistence\NavigationQueryContainer getQueryContainer()
 * @method \Spryker\Zed\Navigation\NavigationConfig getConfig()
 */
class NavigationPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\Navigation\Persistence\SpyNavigationQuery
     */
    public function createNavigationQuery()
    {
        return SpyNavigationQuery::create();
    }

    /**
     * @return \Orm\Zed\Navigation\Persistence\SpyNavigationNodeQuery
     */
    public function createNavigationNodeQuery()
    {
        return SpyNavigationNodeQuery::create();
    }

    /**
     * @return \Orm\Zed\Navigation\Persistence\SpyNavigationNodeLocalizedAttributesQuery
     */
    public function createNavigationNodeLocalizedAttributesQuery()
    {
        return SpyNavigationNodeLocalizedAttributesQuery::create();
    }
}
