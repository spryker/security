<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CategoryImageStorage\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\CategoryImageStorage\Business\CategoryImageStorageBusinessFactory getFactory()
 * @method \Spryker\Zed\CategoryImageStorage\Persistence\CategoryImageStorageEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\CategoryImageStorage\Persistence\CategoryImageStorageRepositoryInterface getRepository()
 */
class CategoryImageStorageFacade extends AbstractFacade implements CategoryImageStorageFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $categoryIds
     *
     * @return void
     */
    public function publishCategoryImages(array $categoryIds)
    {
        $this->getFactory()->createCategoryImageStorageWriter()->publish($categoryIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $categoryIds
     *
     * @return void
     */
    public function unpublishCategoryImages(array $categoryIds)
    {
        $this->getFactory()->createCategoryImageStorageWriter()->unpublish($categoryIds);
    }
}
