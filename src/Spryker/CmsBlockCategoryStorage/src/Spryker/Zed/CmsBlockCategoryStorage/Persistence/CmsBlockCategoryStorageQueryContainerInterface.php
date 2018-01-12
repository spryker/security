<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockCategoryStorage\Persistence;

use Spryker\Zed\Kernel\Persistence\QueryContainer\QueryContainerInterface;

interface CmsBlockCategoryStorageQueryContainerInterface extends QueryContainerInterface
{
    /**
     * @api
     *
     * @param array $categoryIds
     *
     * @return \Orm\Zed\CmsBlockCategoryStorage\Persistence\SpyCmsBlockCategoryStorageQuery
     */
    public function queryCmsBlockCategoryStorageByIds(array $categoryIds);

    /**
     * @api
     *
     * @param array $categoryIds
     *
     * @return $this|\Orm\Zed\CmsBlockCategoryConnector\Persistence\SpyCmsBlockCategoryConnectorQuery
     */
    public function queryCmsBlockCategories(array $categoryIds);

    /**
     * @api
     *
     * @param array $idPositions
     *
     * @return \Orm\Zed\CmsBlockCategoryConnector\Persistence\SpyCmsBlockCategoryConnectorQuery
     */
    public function queryCategoryIdsByPositionIds(array $idPositions);
}
