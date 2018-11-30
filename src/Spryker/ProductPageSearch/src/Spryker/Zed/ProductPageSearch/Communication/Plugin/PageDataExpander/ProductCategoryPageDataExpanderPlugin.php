<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPageSearch\Communication\Plugin\PageDataExpander;

use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\ProductPageSearchTransfer;
use Spryker\Zed\Category\Persistence\CategoryQueryContainer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductCategory\Persistence\ProductCategoryQueryContainer;
use Spryker\Zed\ProductPageSearch\Dependency\Plugin\ProductPageDataExpanderInterface;

/**
 * @deprecated Use \Spryker\Zed\ProductPageSearch\Communication\Plugin\PageDataExpander\ProductCategoryPageDataLoaderExpanderPlugin instead.
 *
 * @method \Spryker\Zed\ProductPageSearch\Persistence\ProductPageSearchQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductPageSearch\Communication\ProductPageSearchCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductPageSearch\Business\ProductPageSearchFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductPageSearch\ProductPageSearchConfig getConfig()
 */
class ProductCategoryPageDataExpanderPlugin extends AbstractPlugin implements ProductPageDataExpanderInterface
{
    public const RESULT_FIELD_PRODUCT_ORDER = 'product_order';

    /**
     * @var array|null
     */
    protected static $categoryTree;

    /**
     * @var array|null
     */
    protected static $categoryName;

    /**
     * @api
     *
     * @param array $productData
     * @param \Generated\Shared\Transfer\ProductPageSearchTransfer $productAbstractPageSearchTransfer
     *
     * @return void
     */
    public function expandProductPageData(array $productData, ProductPageSearchTransfer $productAbstractPageSearchTransfer): void
    {
        $allParentCategoryIds = [];
        foreach ($productAbstractPageSearchTransfer->getCategoryNodeIds() as $idCategory) {
            $allParentCategoryIds = array_merge(
                $allParentCategoryIds,
                $this->getAllParents($idCategory)
            );
        }

        $allParentCategoryIds = array_values(array_unique($allParentCategoryIds));
        $productAbstractPageSearchTransfer->setAllParentCategoryIds($allParentCategoryIds);
        $localeTransfer = (new LocaleTransfer())->setIdLocale($productData['Locale']['id_locale']);

        $this->setCategoryNames(
            $allParentCategoryIds,
            $productAbstractPageSearchTransfer->getCategoryNodeIds(),
            $localeTransfer,
            $productAbstractPageSearchTransfer
        );

        $this->setSorting(
            $allParentCategoryIds,
            $productData['fk_product_abstract'],
            $productAbstractPageSearchTransfer
        );
    }

    /**
     * @param int $idCategoryNode
     *
     * @return array
     */
    protected function getAllParents($idCategoryNode): array
    {
        if (static::$categoryTree === null) {
            $this->loadTree();
        }

        return static::$categoryTree[$idCategoryNode];
    }

    /**
     * @return void
     */
    protected function loadTree(): void
    {
        static::$categoryTree = [];

        $categoryNodes = $this->getFactory()->getCategoryQueryContainer()
            ->queryAllCategoryNodes()
            ->find();

        foreach ($categoryNodes as $categoryNodeEntity) {
            $pathData = $this->getFactory()->getCategoryQueryContainer()
                ->queryFullPath($categoryNodeEntity->getIdCategoryNode())
                ->find();

            static::$categoryTree[$categoryNodeEntity->getIdCategoryNode()] = [];

            foreach ($pathData as $path) {
                $idCategory = (int)$path[CategoryQueryContainer::ID_CATEGORY_NODE_ALIAS];
                if (!in_array($idCategory, static::$categoryTree[$categoryNodeEntity->getIdCategoryNode()])) {
                    static::$categoryTree[$categoryNodeEntity->getIdCategoryNode()][] = $idCategory;
                }
            }
        }
    }

    /**
     * @param array $allParentCategories
     * @param array $directParentCategories
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param \Generated\Shared\Transfer\ProductPageSearchTransfer $productAbstractPageSearchTransfer
     *
     * @return void
     */
    protected function setCategoryNames(
        array $allParentCategories,
        array $directParentCategories,
        LocaleTransfer $localeTransfer,
        ProductPageSearchTransfer $productAbstractPageSearchTransfer
    ) {
        $boostedCategoryNames = [];
        foreach ($directParentCategories as $idCategory) {
            $boostedName = $this->getName($idCategory, $localeTransfer);
            if ($boostedName !== null) {
                $boostedCategoryNames[$idCategory] = $boostedName;
            }
        }
        $productAbstractPageSearchTransfer->setBoostedCategoryNames($boostedCategoryNames);

        $categoryNames = [];
        foreach ($allParentCategories as $idCategory) {
            if (in_array($idCategory, $directParentCategories)) {
                continue;
            }

            $categoryName = $this->getName($idCategory, $localeTransfer);
            if ($categoryName !== null) {
                $categoryNames[$idCategory] = $categoryName;
            }
        }
        $productAbstractPageSearchTransfer->setCategoryNames($categoryNames);
    }

    /**
     * @param int $idCategory
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @return string
     */
    protected function getName($idCategory, LocaleTransfer $localeTransfer)
    {
        if (static::$categoryName === null) {
            $this->loadNames($localeTransfer);
        }

        return isset(static::$categoryName[$idCategory]) ? static::$categoryName[$idCategory] : null;
    }

    /**
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @return void
     */
    protected function loadNames(LocaleTransfer $localeTransfer)
    {
        static::$categoryName = [];

        $categoryAttributes = $this
            ->getQueryContainer()
            ->queryCategoryAttributesByLocale($localeTransfer)
            ->useCategoryQuery()
            ->filterByIsSearchable(true)
            ->endUse()
            ->find();

        foreach ($categoryAttributes as $categoryAttributeEntity) {
            static::$categoryName[$categoryAttributeEntity->getFkCategory()] = $categoryAttributeEntity->getName();
        }
    }

    /**
     * @param array $directParentCategories
     * @param int $idProductAbstract
     * @param \Generated\Shared\Transfer\ProductPageSearchTransfer $productAbstractPageSearchTransfer
     *
     * @return void
     */
    protected function setSorting(
        array $directParentCategories,
        $idProductAbstract,
        ProductPageSearchTransfer $productAbstractPageSearchTransfer
    ) {
        $maxProductOrder = (pow(2, 31) - 1);
        $productCategoryEntities = $this->findNodeEntitiesWithProductOrderPosition(
            $directParentCategories,
            $idProductAbstract
        );

        $sortedCategories = [];
        foreach ($productCategoryEntities as $productCategoryEntity) {
            $idCategoryNode = $productCategoryEntity->getVirtualColumn(
                ProductCategoryQueryContainer::VIRTUAL_COLUMN_ID_CATEGORY_NODE
            );

            $productOrder = (int)$productCategoryEntity->getProductOrder() ?: $maxProductOrder;
            $sortedCategories[$idCategoryNode]['product_order'] = $productOrder;
            $allNodeParents = $this->getAllParents($idCategoryNode);
            $sortedCategories[$idCategoryNode]['all_node_parents'] = $allNodeParents;
        }
        $productAbstractPageSearchTransfer->setSortedCategories($sortedCategories);
    }

    /**
     * @param int[] $directParentCategories
     * @param int $idProductAbstract
     *
     * @return \Orm\Zed\ProductCategory\Persistence\SpyProductCategory[]|\Propel\Runtime\Collection\ObjectCollection
     */
    protected function findNodeEntitiesWithProductOrderPosition(array $directParentCategories, $idProductAbstract)
    {
        return $this
            ->getFactory()->getProductCategoryQueryContainer()
            ->queryProductCategoryMappingsByIdAbstractProductAndIdsCategoryNode(
                $idProductAbstract,
                $directParentCategories
            )
            ->find();
    }
}
