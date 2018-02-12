<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSetStorage\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductSetStorage\Business\ProductSetStorageBusinessFactory getFactory()
 */
class ProductSetStorageFacade extends AbstractFacade implements ProductSetStorageFacadeInterface
{
    /**
     * @api
     *
     * @param array $productSetIds
     *
     * @return void
     */
    public function publish(array $productSetIds)
    {
        $this->getFactory()->createProductSetStorageWriter()->publish($productSetIds);
    }

    /**
     * @api
     *
     * @param array $productSetIds
     *
     * @return void
     */
    public function unpublish(array $productSetIds)
    {
        $this->getFactory()->createProductSetStorageWriter()->unpublish($productSetIds);
    }
}
