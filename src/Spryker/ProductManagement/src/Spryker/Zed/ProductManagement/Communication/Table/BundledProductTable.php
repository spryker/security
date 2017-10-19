<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductManagement\Communication\Table;

use Generated\Shared\Transfer\LocaleTransfer;
use Orm\Zed\Product\Persistence\Map\SpyProductLocalizedAttributesTableMap;
use Orm\Zed\Product\Persistence\Map\SpyProductTableMap;
use Orm\Zed\Product\Persistence\SpyProduct;
use Orm\Zed\ProductBundle\Persistence\Map\SpyProductBundleTableMap;
use Orm\Zed\Stock\Persistence\Map\SpyStockProductTableMap;
use Propel\Runtime\ActiveQuery\Criteria;
use Spryker\Service\UtilText\Model\Url\Url;
use Spryker\Zed\Gui\Communication\Table\AbstractTable;
use Spryker\Zed\Gui\Communication\Table\TableConfiguration;
use Spryker\Zed\Product\Persistence\ProductQueryContainerInterface;
use Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToAvailabilityInterface;
use Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToMoneyInterface;
use Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToPriceInterface;
use Spryker\Zed\ProductManagement\Dependency\Service\ProductManagementToUtilEncodingInterface;

class BundledProductTable extends AbstractTable
{
    const COL_SELECT = 'select';
    const COL_PRICE = 'price';
    const COL_AVAILABILITY = 'availability';
    const COL_ID_PRODUCT_CONCRETE = 'id_product_concrete';
    const SPY_PRODUCT_LOCALIZED_ATTRIBUTE_ALIAS_NAME = 'Name';
    const IS_NEVER_OUT_OF_STOCK = 'isNeverOutOfStock';

    /**
     * @var \Spryker\Zed\Product\Persistence\ProductQueryContainerInterface
     */
    protected $productQueryContainer;

    /**
     * @var \Spryker\Zed\ProductManagement\Dependency\Service\ProductManagementToUtilEncodingInterface
     */
    protected $utilEncodingService;

    /**
     * @var \Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToPriceInterface
     */
    protected $priceFacade;

    /**
     * @var \Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToMoneyInterface
     */
    protected $moneyFacade;

    /**
     * @var \Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToAvailabilityInterface
     */
    protected $availabilityFacade;

    /**
     * @var int
     */
    protected $idProductConcrete;

    /**
     * @var \Generated\Shared\Transfer\LocaleTransfer
     */
    protected $localeTransfer;

    /**
     * @param \Spryker\Zed\Product\Persistence\ProductQueryContainerInterface $productQueryContainer
     * @param \Spryker\Zed\ProductManagement\Dependency\Service\ProductManagementToUtilEncodingInterface $utilEncodingService
     * @param \Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToPriceInterface $priceFacade
     * @param \Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToMoneyInterface $moneyFacade
     * @param \Spryker\Zed\ProductManagement\Dependency\Facade\ProductManagementToAvailabilityInterface $availabilityFacade
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param int|null $idProductConcrete
     */
    public function __construct(
        ProductQueryContainerInterface $productQueryContainer,
        ProductManagementToUtilEncodingInterface $utilEncodingService,
        ProductManagementToPriceInterface $priceFacade,
        ProductManagementToMoneyInterface $moneyFacade,
        ProductManagementToAvailabilityInterface $availabilityFacade,
        LocaleTransfer $localeTransfer,
        $idProductConcrete = null
    ) {
        $this->setTableIdentifier('bundled-product-table');
        $this->productQueryContainer = $productQueryContainer;
        $this->utilEncodingService = $utilEncodingService;
        $this->priceFacade = $priceFacade;
        $this->moneyFacade = $moneyFacade;
        $this->availabilityFacade = $availabilityFacade;
        $this->idProductConcrete = $idProductConcrete;
        $this->localeTransfer = $localeTransfer;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function configure(TableConfiguration $config)
    {
        $config->setUrl(
            sprintf(
                'bundledProductTable?id-product-concrete=%d',
                $this->idProductConcrete
            )
        );

        $config->setHeader([
            static::COL_SELECT => 'Select',
            static::COL_ID_PRODUCT_CONCRETE => 'id product',
            SpyProductLocalizedAttributesTableMap::COL_NAME => 'Product name',
            SpyProductTableMap::COL_SKU => 'SKU',
            static::COL_PRICE => 'Price',
            SpyStockProductTableMap::COL_QUANTITY => 'Stock',
            static::COL_AVAILABILITY => 'Availability',
            SpyStockProductTableMap::COL_IS_NEVER_OUT_OF_STOCK => 'Is never out of stock',
        ]);

        $config->setRawColumns([
            static::COL_SELECT,
            static::COL_PRICE,
            static::COL_AVAILABILITY,
            SpyProductTableMap::COL_SKU,
        ]);

        $config->setSearchable([
            SpyProductLocalizedAttributesTableMap::COL_NAME,
            SpyProductTableMap::COL_SKU,
        ]);

        $config->setSortable([
            SpyProductLocalizedAttributesTableMap::COL_NAME,
            SpyProductTableMap::COL_SKU,
            SpyStockProductTableMap::COL_QUANTITY,
            SpyStockProductTableMap::COL_IS_NEVER_OUT_OF_STOCK,
        ]);

        return $config;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return array
     */
    protected function prepareData(TableConfiguration $config)
    {
        $query = $this
            ->productQueryContainer
            ->queryProduct()
            ->leftJoinSpyProductBundleRelatedByFkProduct()
            ->joinSpyProductLocalizedAttributes()
            ->joinStockProduct()
            ->withColumn(SpyProductLocalizedAttributesTableMap::COL_NAME, self::SPY_PRODUCT_LOCALIZED_ATTRIBUTE_ALIAS_NAME)
            ->withColumn(sprintf('SUM(%s)', SpyStockProductTableMap::COL_QUANTITY), 'stockQuantity')
            ->withColumn(SpyStockProductTableMap::COL_IS_NEVER_OUT_OF_STOCK, self::IS_NEVER_OUT_OF_STOCK)
            ->where(SpyProductLocalizedAttributesTableMap::COL_FK_LOCALE . ' = ?', $this->localeTransfer->getIdLocale())
            ->add(SpyProductBundleTableMap::COL_ID_PRODUCT_BUNDLE, null, Criteria::ISNULL)
            ->groupBy(SpyProductTableMap::COL_ID_PRODUCT)
            ->addGroupByColumn(self::SPY_PRODUCT_LOCALIZED_ATTRIBUTE_ALIAS_NAME)
            ->addGroupByColumn(self::IS_NEVER_OUT_OF_STOCK);

        $queryResults = $this->runQuery($query, $config, true);

        $productAbstractCollection = [];
        foreach ($queryResults as $item) {
            $productAbstractCollection[] = [
                static::COL_SELECT => $this->addCheckBox($item),
                static::COL_ID_PRODUCT_CONCRETE => $item->getIdProduct(),
                SpyProductLocalizedAttributesTableMap::COL_NAME => $item->getName(),
                SpyProductTableMap::COL_SKU => $this->getProductEditPageLink($item->getSku(), $item->getFkProductAbstract(), $item->getIdProduct()),
                static::COL_PRICE => $this->getFormatedPrice($item->getSku()),
                SpyStockProductTableMap::COL_QUANTITY => $item->getStockQuantity(),
                static::COL_AVAILABILITY => $this->getAvailability($item),
                SpyStockProductTableMap::COL_IS_NEVER_OUT_OF_STOCK => $item->getIsNeverOutOfStock(),
            ];
        }

        return $productAbstractCollection;
    }

    /**
     * @param string $sku
     * @param int $idProductAbstract
     * @param int $idProductConcrete
     *
     * @return string
     */
    protected function getProductEditPageLink($sku, $idProductAbstract, $idProductConcrete)
    {
        $pageEditUrl = Url::generate('/product-management/edit/variant', [
            'id-product-abstract' => $idProductAbstract,
            'id-product' => $idProductConcrete,
        ])->build();

        $pageEditLink = '<a target="_blank" href="' . $pageEditUrl . '">' . $sku . '</a>';

        return $pageEditLink;
    }

    /**
     * @param string $sku
     *
     * @return string
     */
    protected function getFormatedPrice($sku)
    {
        $priceInCents = $this->priceFacade->getPriceBySku($sku);

        $moneyTransfer = $this->moneyFacade->fromInteger($priceInCents);

        return $this->moneyFacade->formatWithSymbol($moneyTransfer);
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProduct $productConcreteEntity
     *
     * @return string
     */
    protected function addCheckBox(SpyProduct $productConcreteEntity)
    {
        $checked = '';
        if ($this->idProductConcrete) {
            $criteria = new Criteria();
            $criteria->add(SpyProductBundleTableMap::COL_FK_PRODUCT, $this->idProductConcrete);

            if ($productConcreteEntity->getSpyProductBundlesRelatedByFkBundledProduct($criteria)->count() > 0) {
                $checked = 'checked="checked"';
            }
        }

        return sprintf(
            "<input id='product_assign_checkbox_%d' class='product_assign_checkbox' type='checkbox' data-info='%s' %s >",
            $productConcreteEntity->getIdProduct(),
            $this->utilEncodingService->encodeJson($productConcreteEntity->toArray()),
            $checked
        );
    }

    /**
     * @param \Orm\Zed\Product\Persistence\SpyProduct $productConcreteEntity
     *
     * @return int
     */
    protected function getAvailability(SpyProduct $productConcreteEntity)
    {
        $availability = 0;
        if (!$productConcreteEntity->getIsNeverOutOfStock()) {
            $availability = $this->availabilityFacade->calculateStockForProduct($productConcreteEntity->getSku());
        }
        return $availability;
    }
}
