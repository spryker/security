<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductCategory\Persistence\Propel\Mapper;

use Propel\Runtime\Collection\ObjectCollection;

interface CategoryMapperInterface
{
    /**
     * @param \Propel\Runtime\Collection\ObjectCollection $spyProductCategoryCollection
     *
     * @return int[]
     */
    public function getIdsCategoryList(ObjectCollection $spyProductCategoryCollection): array;
}
