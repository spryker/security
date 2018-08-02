<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPageSearch\Communication\Plugin\PageDataLoader;

use Generated\Shared\Transfer\ProductPageLoadTransfer;
use Orm\Zed\Category\Persistence\Map\SpyCategoryNodeTableMap;
use Orm\Zed\ProductCategory\Persistence\SpyProductCategoryQuery;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductPageSearch\Dependency\Plugin\ProductPageDataLoaderPluginInterface;

/**
 * @method \Spryker\Zed\ProductPageSearch\Communication\ProductPageSearchCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductPageSearch\Business\ProductPageSearchFacade getFacade()
 */
class CategoryPageDataLoaderPlugin extends AbstractPlugin implements ProductPageDataLoaderPluginInterface
{
    const VIRT_COLUMN_ID_CATEGORY_NODE = 'id_category_node';

    /**
     * @param \Generated\Shared\Transfer\ProductPageLoadTransfer $loadTransfer
     *
     * @return \Generated\Shared\Transfer\ProductPageLoadTransfer
     */
    public function expandProductPageDataTransfer(ProductPageLoadTransfer $loadTransfer)
    {
        $payloadTransfers = $this->setProductCategories($loadTransfer->getProductAbstractIds(), $loadTransfer->getPayloadTransfers());
        $loadTransfer->setPayloadTransfers($payloadTransfers);

        return $loadTransfer;
    }

    /**
     * @return string
     */
    public function getProductPageType()
    {
        return 'category';
    }

    /**
     * @param array $productAbstractIds
     * @param \Generated\Shared\Transfer\ProductPayloadTransfer[] $payloadTransfers
     *
     * @return array
     */
    protected function setProductCategories(array $productAbstractIds, array $payloadTransfers): array
    {
        $query = SpyProductCategoryQuery::create()
            ->filterByFkProductAbstract_In($productAbstractIds)
            ->useSpyCategoryQuery()
                ->useNodeQuery()
                    ->withColumn(SpyCategoryNodeTableMap::COL_ID_CATEGORY_NODE, static::VIRT_COLUMN_ID_CATEGORY_NODE)
                ->endUse()
            ->endUse();

        $productCategoryEntities = $query->find();
        $formattedProductCategories = [];
        foreach ($productCategoryEntities as $productCategoryEntity) {
            $formattedProductCategories[$productCategoryEntity->getFkProductAbstract()][] = $productCategoryEntity;
        }

        foreach ($payloadTransfers as $payloadTransfer) {
            if (!isset($formattedProductCategories[$payloadTransfer->getIdProductAbstract()])) {
                continue;
            }

            $categories = $formattedProductCategories[$payloadTransfer->getIdProductAbstract()];
            $payloadTransfer->setCategories($categories);
        }

        return $payloadTransfers;
    }
}
