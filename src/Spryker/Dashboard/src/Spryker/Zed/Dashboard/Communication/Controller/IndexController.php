<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Dashboard\Communication\Controller;

use Generated\Shared\Transfer\FilterTransfer;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepository;

/**
 * @method \Spryker\Zed\Dashboard\Communication\DashboardCommunicationFactory getFactory()
 */
class IndexController extends AbstractController
{
    /**
     * @return array
     */
    public function indexAction(): array
    {


        $r = new PriceProductMerchantRelationshipStorageRepository();
        $filter = new FilterTransfer();
        $filter->setOffset(0);
        $filter->setLimit(100);

        dump($r->findFilteredPriceProductConcreteMerchantRelationshipStorageEntities($filter));
        die;

        $plugins = $this->getFactory()->getDateFormatterService();

        $pluginContents = [];
        foreach ($plugins as $plugin) {
            $pluginContents[] = $plugin->render();
        }

        return [
            'pluginContents' => $pluginContents,
        ];
    }
}
