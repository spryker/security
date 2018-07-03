<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsStorage\Persistence;

use Spryker\Zed\Kernel\Persistence\QueryContainer\QueryContainerInterface;

interface CmsStorageQueryContainerInterface extends QueryContainerInterface
{
    /**
     * @api
     *
     * @param array $cmsPageIds
     *
     * @return \Orm\Zed\Cms\Persistence\SpyCmsPageQuery
     */
    public function queryCmsPageVersionByIds(array $cmsPageIds);

    /**
     * @api
     *
     * @param array $cmsPageIds
     *
     * @return \Orm\Zed\CmsStorage\Persistence\SpyCmsPageStorageQuery
     */
    public function queryCmsPageStorageEntities(array $cmsPageIds);

    /**
     * @api
     *
     * @param array $localeNames
     *
     * @return \Orm\Zed\Locale\Persistence\SpyLocaleQuery
     */
    public function queryLocalesWithLocaleNames(array $localeNames);
}
