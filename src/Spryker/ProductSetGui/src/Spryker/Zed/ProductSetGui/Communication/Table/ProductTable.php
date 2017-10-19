<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSetGui\Communication\Table;

use Generated\Shared\Transfer\LocaleTransfer;
use Orm\Zed\Product\Persistence\SpyProductAbstract;
use Spryker\Zed\Gui\Communication\Table\AbstractTable;
use Spryker\Zed\Gui\Communication\Table\TableConfiguration;
use Spryker\Zed\ProductSetGui\Communication\Controller\AbstractProductSetController;
use Spryker\Zed\ProductSetGui\Communication\Table\Helper\ProductAbstractTableHelperInterface;
use Spryker\Zed\ProductSetGui\Persistence\ProductSetGuiQueryContainer;
use Spryker\Zed\ProductSetGui\Persistence\ProductSetGuiQueryContainerInterface;

class ProductTable extends AbstractTable
{
    const TABLE_IDENTIFIER = 'product-table';
    const COL_ID_PRODUCT_ABSTRACT = 'id_product_abstract';
    const COL_PREVIEW = 'preview';
    const COL_SKU = 'sku';
    const COL_NAME = ProductSetGuiQueryContainer::COL_ALIAS_NAME;
    const COL_PRICE = 'price';
    const COL_STATUS = 'status';
    const COL_CHECKBOX = 'checkbox';

    /**
     * @var \Spryker\Zed\ProductSetGui\Persistence\ProductSetGuiQueryContainerInterface
     */
    protected $productSetGuiQueryContainer;

    /**
     * @var \Spryker\Zed\ProductSetGui\Communication\Table\Helper\ProductAbstractTableHelperInterface
     */
    protected $productAbstractTableHelper;

    /**
     * @var int
     */
    protected $idProductSetGuiGroup;

    /**
     * @var \Generated\Shared\Transfer\LocaleTransfer
     */
    protected $localeTransfer;

    /**
     * @param \Spryker\Zed\ProductSetGui\Persistence\ProductSetGuiQueryContainerInterface $productSetGuiQueryContainer
     * @param \Spryker\Zed\ProductSetGui\Communication\Table\Helper\ProductAbstractTableHelperInterface $productAbstractTableHelper
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param int|null $idProductSetGuiGroup
     */
    public function __construct(
        ProductSetGuiQueryContainerInterface $productSetGuiQueryContainer,
        ProductAbstractTableHelperInterface $productAbstractTableHelper,
        LocaleTransfer $localeTransfer,
        $idProductSetGuiGroup = null
    ) {
        $this->productSetGuiQueryContainer = $productSetGuiQueryContainer;
        $this->productAbstractTableHelper = $productAbstractTableHelper;
        $this->localeTransfer = $localeTransfer;
        $this->idProductSetGuiGroup = (int)$idProductSetGuiGroup;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function configure(TableConfiguration $config)
    {
        $urlSuffix = $this->idProductSetGuiGroup ? sprintf('?%s=%d', AbstractProductSetController::PARAM_ID, $this->idProductSetGuiGroup) : null;
        $this->defaultUrl = static::TABLE_IDENTIFIER . $urlSuffix;
        $this->setTableIdentifier(static::TABLE_IDENTIFIER);

        $config->setHeader([
            static::COL_ID_PRODUCT_ABSTRACT => 'ID',
            static::COL_PREVIEW => 'Preview',
            static::COL_SKU => 'SKU',
            static::COL_NAME => 'Name',
            static::COL_PRICE => 'Price',
            static::COL_STATUS => 'Status',
            static::COL_CHECKBOX => 'Selected',
        ]);

        $config->setSortable([
            static::COL_ID_PRODUCT_ABSTRACT,
            static::COL_SKU,
            static::COL_NAME,
        ]);

        $config->setSearchable([
            static::COL_ID_PRODUCT_ABSTRACT,
            static::COL_SKU,
            static::COL_NAME,
        ]);

        $config->setRawColumns([
            static::COL_PREVIEW,
            static::COL_STATUS,
            static::COL_CHECKBOX,
        ]);

        $config->setDefaultSortField(static::COL_ID_PRODUCT_ABSTRACT, TableConfiguration::SORT_ASC);
        $config->setStateSave(false);

        return $config;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return array
     */
    protected function prepareData(TableConfiguration $config)
    {
        $query = $this->productSetGuiQueryContainer->queryProductAbstractForAssignment($this->idProductSetGuiGroup, $this->localeTransfer);

        $queryResults = $this->runQuery($query, $config, true);

        $results = [];
        foreach ($queryResults as $productAbstractEntity) {
            $results[] = $this->formatRow($productAbstractEntity);
        }

        return $results;
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductAbstract $productAbstractEntity
     *
     * @return array
     */
    protected function formatRow(SpyProductAbstract $productAbstractEntity)
    {
        return [
            static::COL_ID_PRODUCT_ABSTRACT => $productAbstractEntity->getIdProductAbstract(),
            static::COL_PREVIEW => $this->productAbstractTableHelper->getProductPreview($productAbstractEntity),
            static::COL_SKU => $productAbstractEntity->getSku(),
            static::COL_NAME => $productAbstractEntity->getVirtualColumn(static::COL_NAME),
            static::COL_PRICE => $this->productAbstractTableHelper->getProductPrice($productAbstractEntity),
            static::COL_STATUS => $this->productAbstractTableHelper->getAbstractProductStatusLabel($productAbstractEntity),
            static::COL_CHECKBOX => $this->getSelectField($productAbstractEntity),
        ];
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductAbstract $productAbstractEntity
     *
     * @return string
     */
    protected function getSelectField(SpyProductAbstract $productAbstractEntity)
    {
        $checkbox_html = sprintf(
            '<input id="all_products_checkbox_%1$d" class="all-products-checkbox" type="checkbox" data-id="%1$s">',
            $productAbstractEntity->getIdProductAbstract()
        );

        return $checkbox_html;
    }
}
