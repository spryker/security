<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace Spryker\Zed\ProductListDataImport\Business\Model;

use Orm\Zed\ProductList\Persistence\SpyProductListCategoryQuery;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\DataImportStepInterface;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\PublishAwareStep;
use Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface;
use Spryker\Zed\ProductList\Dependency\ProductListEvents;
use Spryker\Zed\ProductListDataImport\Business\Model\DataSet\ProductListDataSetInterface;

class ProductListToCategoryWriterStep extends PublishAwareStep implements DataImportStepInterface
{
    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return void
     */
    public function execute(DataSetInterface $dataSet): void
    {
        $this->saveProductListCategory($dataSet);
    }

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return void
     */
    protected function saveProductListCategory(DataSetInterface $dataSet): void
    {
        $productListCategoryEntity = SpyProductListCategoryQuery::create()
            ->filterByFkProductList($dataSet[ProductListDataSetInterface::ID_PRODUCT_LIST])
            ->filterByFkCategory($dataSet[ProductListDataSetInterface::ID_CATEGORY])
            ->findOneOrCreate();

        $productListCategoryEntity->setFkProductList($dataSet[ProductListDataSetInterface::ID_PRODUCT_LIST])
            ->setFkCategory($dataSet[ProductListDataSetInterface::ID_CATEGORY])
            ->save();

        $this->addPublishEvents(
            ProductListEvents::PRODUCT_LIST_CATEGORY_PUBLISH,
            $productListCategoryEntity->getFkCategory()
        );
    }
}
