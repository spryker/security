<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockCategoryStorage\Persistence;

use Orm\Zed\Category\Persistence\Map\SpyCategoryTableMap;
use Orm\Zed\CmsBlock\Persistence\Map\SpyCmsBlockTableMap;
use Orm\Zed\CmsBlockCategoryConnector\Persistence\Map\SpyCmsBlockCategoryConnectorTableMap;
use Orm\Zed\CmsBlockCategoryConnector\Persistence\Map\SpyCmsBlockCategoryPositionTableMap;
use Propel\Runtime\ActiveQuery\Criteria;
use Spryker\Zed\Kernel\Persistence\AbstractQueryContainer;

/**
 * @method \Spryker\Zed\CmsBlockCategoryStorage\Persistence\CmsBlockCategoryStoragePersistenceFactory getFactory()
 */
class CmsBlockCategoryStorageQueryContainer extends AbstractQueryContainer implements CmsBlockCategoryStorageQueryContainerInterface
{
    const POSITION = 'position';
    const NAME = 'name';

    /**
     * @api
     *
     * @param array $categoryIds
     *
     * @return $this|\Orm\Zed\CmsBlockCategoryStorage\Persistence\SpyCmsBlockCategoryStorageQuery
     */
    public function queryCmsBlockCategoryStorageByIds(array $categoryIds)
    {
        return $this->getFactory()
            ->createSpyCmsBlockCategoryStorageQuery()
            ->filterByFkCategory_In($categoryIds);
    }

    /**
     * @api
     *
     * @param array $categoryIds
     *
     * @return $this|\Orm\Zed\CmsBlockCategoryConnector\Persistence\SpyCmsBlockCategoryConnectorQuery
     */
    public function queryCmsBlockCategories(array $categoryIds)
    {
        return $this->getFactory()
            ->getCmsBlockCategoryConnectorQuery()
            ->queryCmsBlockCategoryConnector()
            ->innerJoinCmsBlockCategoryPosition()
            ->innerJoinCmsBlock()
            ->addJoin(
                [SpyCmsBlockCategoryConnectorTableMap::COL_FK_CATEGORY, SpyCmsBlockCategoryConnectorTableMap::COL_FK_CATEGORY_TEMPLATE],
                [SpyCategoryTableMap::COL_ID_CATEGORY, SpyCategoryTableMap::COL_FK_CATEGORY_TEMPLATE],
                Criteria::INNER_JOIN
            )
            ->withColumn(SpyCmsBlockCategoryPositionTableMap::COL_NAME, static::POSITION)
            ->withColumn(SpyCmsBlockTableMap::COL_NAME, static::NAME)
            ->filterByFkCategory_In($categoryIds);
    }

    /**
     * @api
     *
     * @param array $idPositions
     *
     * @return \Orm\Zed\CmsBlockCategoryConnector\Persistence\SpyCmsBlockCategoryConnectorQuery
     */
    public function queryCategoryIdsByPositionIds(array $idPositions)
    {
        return $this->getFactory()
            ->getCmsBlockCategoryConnectorQuery()
            ->queryCmsBlockCategoryConnector()
            ->filterByFkCmsBlockCategoryPosition_In($idPositions)
            ->select([SpyCmsBlockCategoryConnectorTableMap::COL_FK_CATEGORY]);
    }
}
