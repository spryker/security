<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSetStorage\Communication\Plugin\Event;

use Orm\Zed\ProductSet\Persistence\Map\SpyProductSetTableMap;
use Propel\Runtime\ActiveQuery\ModelCriteria;
use Spryker\Shared\ProductSetStorage\ProductSetStorageConstants;
use Spryker\Zed\EventBehavior\Dependency\Plugin\EventResourceQueryContainerPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductSet\Dependency\ProductSetEvents;

/**
 * @method \Spryker\Zed\ProductSetStorage\Persistence\ProductSetStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductSetStorage\Business\ProductSetStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductSetStorage\Communication\ProductSetStorageCommunicationFactory getFactory()
 */
class ProductSetEventResourceQueryContainerPlugin extends AbstractPlugin implements EventResourceQueryContainerPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getResourceName(): string
    {
        return ProductSetStorageConstants::PRODUCT_SET_RESOURCE_NAME;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $ids
     *
     * @return \Propel\Runtime\ActiveQuery\ModelCriteria|null
     */
    public function queryData(array $ids = []): ?ModelCriteria
    {
        $query = $this->getQueryContainer()->queryProductSetByIds($ids);

        if (empty($ids)) {
            $query->clear();
        }

        return $query;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getEventName(): string
    {
        return ProductSetEvents::PRODUCT_SET_PUBLISH;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getIdColumnName(): string
    {
        return SpyProductSetTableMap::COL_ID_PRODUCT_SET;
    }
}
