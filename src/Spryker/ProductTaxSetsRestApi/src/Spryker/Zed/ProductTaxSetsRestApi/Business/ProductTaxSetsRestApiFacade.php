<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductTaxSetsRestApi\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductTaxSetsRestApi\Business\ProductTaxSetsRestApiBusinessFactory getFactory()
 * @method \Spryker\Zed\ProductTaxSetsRestApi\Persistence\ProductTaxSetsRestApiEntityManagerInterface getEntityManager()
 */
class ProductTaxSetsRestApiFacade extends AbstractFacade implements ProductTaxSetsRestApiFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @deprecated Use Spryker\Zed\UtilUuidGenerator\Communication\Console\UuidGeneratorConsole instead.
     *
     * @return void
     */
    public function updateTaxSetsWithoutUuid(): void
    {
        $this->getFactory()
            ->createTaxSetWriter()
            ->updateTaxSetsWithoutUuid();
    }
}
