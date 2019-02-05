<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CategoryImage\Communication\Plugin;

use Generated\Shared\Transfer\CategoryTransfer;
use Spryker\Zed\CategoryExtension\Dependency\Plugin\CategoryUpdateAfterPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\CategoryImage\Business\CategoryImageFacadeInterface getFacade()
 * @method \Spryker\Zed\CategoryImage\CategoryImageConfig getConfig()
 */
class CategoryImageSetUpdaterPlugin extends AbstractPlugin implements CategoryUpdateAfterPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CategoryTransfer $categoryTransfer
     *
     * @return void
     */
    public function execute(CategoryTransfer $categoryTransfer): void
    {
        $this->getFacade()->updateCategoryImageSetsForCategory($categoryTransfer);
    }
}
