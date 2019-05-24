<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ContentProductGui\Communication\Table;

use Generated\Shared\Transfer\LocaleTransfer;
use Orm\Zed\Product\Persistence\SpyProductAbstract;
use Orm\Zed\Product\Persistence\SpyProductAbstractQuery;
use Orm\Zed\Product\Persistence\SpyProductAbstractStore;
use Spryker\Zed\ContentProductGui\Communication\Table\Manager\ProductAbstractTableManagerInterface;
use Spryker\Zed\Gui\Communication\Table\AbstractTable;
use Spryker\Zed\Gui\Communication\Table\TableConfiguration;

class ProductAbstractViewTable extends AbstractTable
{
    public const TABLE_IDENTIFIER = 'product-abstract-view-table';
    public const TABLE_CLASS = 'product-abstract-view-table gui-table-data';
    public const BASE_URL = '/content-product-gui/product-abstract/';

    public const HEADER_NAME = 'Name';
    public const HEADER_SKU = 'SKU';
    public const HEADER_ID_PRODUCT_ABSTRACT = 'ID';

    public const COL_ID_PRODUCT_ABSTRACT = 'id_product_abstract';
    public const COL_SKU = 'sku';
    public const COL_IMAGE = 'Image';
    public const COL_NAME = 'name';
    public const COL_STORES = 'Stores';
    public const COL_STATUS = 'Status';
    public const COL_SELECTED = 'Selected';

    public const COL_ALIAS_NAME = 'name';

    /**
     * @var \Orm\Zed\Product\Persistence\SpyProductAbstractQuery
     */
    protected $productQueryContainer;

    /**
     * @var \Spryker\Zed\ContentProductGui\Communication\Table\Manager\ProductAbstractTableManagerInterface
     */
    protected $productAbstractTableManager;

    /**
     * @var \Generated\Shared\Transfer\LocaleTransfer
     */
    protected $localeTransfer;

    /**
     * @var string|null
     */
    protected $identifierSuffix;

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductAbstractQuery $productQueryContainer
     * @param \Spryker\Zed\ContentProductGui\Communication\Table\Manager\ProductAbstractTableManagerInterface $productAbstractTableManager
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param string|null $identifierSuffix
     */
    public function __construct(
        SpyProductAbstractQuery $productQueryContainer,
        ProductAbstractTableManagerInterface $productAbstractTableManager,
        LocaleTransfer $localeTransfer,
        ?string $identifierSuffix
    ) {
        $this->productQueryContainer = $productQueryContainer;
        $this->productAbstractTableManager = $productAbstractTableManager;
        $this->localeTransfer = $localeTransfer;
        $this->identifierSuffix = $identifierSuffix;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function configure(TableConfiguration $config): TableConfiguration
    {
        $this->baseUrl = static::BASE_URL;
        $this->defaultUrl = static::TABLE_IDENTIFIER;
        $this->tableClass = static::TABLE_CLASS;

        $identifierSuffix = !$this->identifierSuffix ?
            static::TABLE_IDENTIFIER :
            sprintf('%s-%s', static::TABLE_IDENTIFIER, $this->identifierSuffix);
        $this->setTableIdentifier($identifierSuffix);

        $config->setHeader([
            static::COL_ID_PRODUCT_ABSTRACT => static::HEADER_ID_PRODUCT_ABSTRACT,
            static::COL_SKU => static::HEADER_SKU,
            static::COL_IMAGE => static::COL_IMAGE,
            static::COL_NAME => static::HEADER_NAME,
            static::COL_STORES => static::COL_STORES,
            static::COL_STATUS => static::COL_STATUS,
            static::COL_SELECTED => static::COL_SELECTED,
        ]);

        $config->setSearchable([
            static::COL_ID_PRODUCT_ABSTRACT,
            static::COL_SKU,
            static::COL_NAME,
        ]);

        $config->setRawColumns([
            static::COL_IMAGE,
            static::COL_STORES,
            static::COL_STATUS,
            static::COL_SELECTED,
        ]);

        $config->setStateSave(false);

        return $config;
    }

    /**
     * @module Product
     *
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return array
     */
    protected function prepareData(TableConfiguration $config): array
    {
        $query = $this->productQueryContainer
            ->useSpyProductAbstractLocalizedAttributesQuery()
                ->filterByFkLocale($this->localeTransfer->getIdLocale())
            ->endUse();
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
    protected function formatRow(SpyProductAbstract $productAbstractEntity): array
    {
        $idProductAbstract = $productAbstractEntity->getIdProductAbstract();

        return [
            static::COL_ID_PRODUCT_ABSTRACT => $idProductAbstract,
            static::COL_SKU => $productAbstractEntity->getSku(),
            static::COL_IMAGE => $this->getProductPreview($this->productAbstractTableManager->getProductPreviewUrl($productAbstractEntity)),
            static::COL_NAME => $productAbstractEntity->getSpyProductAbstractLocalizedAttributess()->getFirst()->getName(),
            static::COL_STORES => $this->getStoreNames($productAbstractEntity->getSpyProductAbstractStores()->getArrayCopy()),
            static::COL_STATUS => $this->getStatusLabel($this->productAbstractTableManager->getAbstractProductStatus($productAbstractEntity)),
            static::COL_SELECTED => $this->getAddButtonField($productAbstractEntity->getIdProductAbstract()),
        ];
    }

    /**
     * @param int $idProductAbstract
     *
     * @return string
     */
    protected function getAddButtonField(int $idProductAbstract): string
    {
        return $this->generateButton(
            '#',
            'Add to list',
            [
                'class' => 'btn-create js-add-product-abstract',
                'data-id' => $idProductAbstract,
                'icon' => 'fa-plus',
                'onclick' => 'return false;',
            ]
        );
    }

    /**
     * @param bool $status
     *
     * @return string
     */
    protected function getStatusLabel(bool $status): string
    {
        if (!$status) {
            return $this->generateLabel('Inactive', 'label-danger');
        }

        return $this->generateLabel('Active', 'label-info');
    }

    /**
     * @param string $link
     *
     * @return string
     */
    protected function getProductPreview(string $link): string
    {
        if ($link) {
            return sprintf('<img src="%s">', $link);
        }

        return '';
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProductAbstractStore[] $productAbstractStoreEntities
     *
     * @return string
     */
    protected function getStoreNames(array $productAbstractStoreEntities): string
    {
        return array_reduce(
            $productAbstractStoreEntities,
            function (string $accumulator, SpyProductAbstractStore $productAbstractStoreEntity): string {
                return $accumulator . " " . $this->generateLabel($productAbstractStoreEntity->getSpyStore()->getName(), 'label-info');
            },
            ""
        );
    }
}
