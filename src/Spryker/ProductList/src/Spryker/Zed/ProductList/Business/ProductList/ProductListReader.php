<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductList\Business\ProductList;

use Generated\Shared\Transfer\ProductListCategoryRelationTransfer;
use Generated\Shared\Transfer\ProductListProductConcreteRelationTransfer;
use Generated\Shared\Transfer\ProductListTransfer;
use Orm\Zed\ProductList\Persistence\Map\SpyProductListProductConcreteTableMap;
use Orm\Zed\ProductList\Persistence\Map\SpyProductListTableMap;
use Spryker\Zed\ProductList\Business\ProductListCategoryRelation\ProductListCategoryRelationReaderInterface;
use Spryker\Zed\ProductList\Business\ProductListProductConcreteRelation\ProductListProductConcreteRelationReaderInterface;
use Spryker\Zed\ProductList\Persistence\ProductListRepository;
use Spryker\Zed\ProductList\Persistence\ProductListRepositoryInterface;

class ProductListReader implements ProductListReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductList\Persistence\ProductListRepositoryInterface
     */
    protected $productListRepository;

    /**
     * @var \Spryker\Zed\ProductList\Business\ProductListCategoryRelation\ProductListCategoryRelationReaderInterface
     */
    protected $productListCategoryRelationReader;

    /**
     * @var \Spryker\Zed\ProductList\Business\ProductListProductConcreteRelation\ProductListProductConcreteRelationReaderInterface
     */
    private $productListProductConcreteRelationReader;

    /**
     * @param \Spryker\Zed\ProductList\Persistence\ProductListRepositoryInterface $productListRepository
     * @param \Spryker\Zed\ProductList\Business\ProductListCategoryRelation\ProductListCategoryRelationReaderInterface $productListCategoryRelationReader
     * @param \Spryker\Zed\ProductList\Business\ProductListProductConcreteRelation\ProductListProductConcreteRelationReaderInterface $productListProductConcreteRelationReader
     */
    public function __construct(
        ProductListRepositoryInterface $productListRepository,
        ProductListCategoryRelationReaderInterface $productListCategoryRelationReader,
        ProductListProductConcreteRelationReaderInterface $productListProductConcreteRelationReader
    ) {
        $this->productListRepository = $productListRepository;
        $this->productListCategoryRelationReader = $productListCategoryRelationReader;
        $this->productListProductConcreteRelationReader = $productListProductConcreteRelationReader;
    }

    /**
     * @param int $idProductAbstract
     *
     * @return int[]
     */
    public function getProductBlacklistIdsByIdProductAbstract(int $idProductAbstract): array
    {
        return $this->productListRepository->getProductBlacklistIdsByIdProductAbstract($idProductAbstract);
    }

    /**
     * @param int[] $productIds
     *
     * @return array
     */
    public function getProductListsByProductIds(array $productIds): array
    {
        $concreteToAbstractMap = $this->productListRepository
            ->getProductAbstractIdsByProductIds($productIds);

        $productConcreteLists = $this->mapProductListIdsByIdProductConcreteAndType(
            $this->productListRepository->getProductListIdsByProductIds($productIds)
        );

        $productAbstractLists = $this->getProductAbstractListsByProductAbstractIds(
            array_values($concreteToAbstractMap)
        );

        return $this->mergeProductConcreteAndProductAbstractLists($productConcreteLists, $productAbstractLists, $concreteToAbstractMap);
    }

    /**
     * @param array $productConcreteLists
     * @param array $productAbstractLists
     * @param array $concreteToAbstractMap
     *
     * @return array
     */
    protected function mergeProductConcreteAndProductAbstractLists(array $productConcreteLists, array $productAbstractLists, array $concreteToAbstractMap): array
    {
        $mergedProductConcreteAndProductAbstractLists = [];
        foreach ($productConcreteLists as $idProductConcrete => $productConcreteList) {
            $idProductAbstract = $concreteToAbstractMap[$idProductConcrete];

            $mergedProductConcreteAndProductAbstractLists[$idProductConcrete] = $productAbstractLists[$idProductAbstract] + $productConcreteList;
        }

        return $mergedProductConcreteAndProductAbstractLists;
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return array
     */
    public function getProductAbstractListsByProductAbstractIds(array $productAbstractIds): array
    {
        $productListIds = $this->filterProductListIds(
            $this->getProductListsByIdProductAbstractIn($productAbstractIds),
            $this->getProductConcreteCountByProductAbstractIds($productAbstractIds)
        );

        $categoryProductList = $this->getCategoryProductList($productAbstractIds);

        $totalProductList = array_merge($productListIds, $categoryProductList);

        return $this->mapProductListIdsByIdProductAbstractAndType($totalProductList);
    }

    /**
     * @param array $productAbstractListsIds
     *
     * @return array
     */
    protected function mapProductListIdsByIdProductAbstractAndType(array $productAbstractListsIds): array
    {
        $mappedProductListIds = [];
        foreach ($productAbstractListsIds as $productList) {
            $idProductAbstract = $productList[ProductListRepository::COL_ID_PRODUCT_ABSTRACT];
            $type = $productList[ProductListRepository::COL_TYPE];
            $idProductList = $productList[ProductListRepository::COL_ID_PRODUCT_LIST];

            $mappedProductListIds[$idProductAbstract][$type][] = $idProductList;
        }

        return $mappedProductListIds;
    }

    /**
     * @param array $productConcreteListsIds
     *
     * @return array
     */
    protected function mapProductListIdsByIdProductConcreteAndType(array $productConcreteListsIds): array
    {
        $mappedProductListIds = [];
        foreach ($productConcreteListsIds as $productList) {
            $idProduct = $productList[SpyProductListProductConcreteTableMap::COL_FK_PRODUCT];
            $type = $productList[ProductListRepository::COL_TYPE];
            $idProductList = $productList[ProductListRepository::COL_ID_PRODUCT_LIST];

            $mappedProductListIds[$idProduct][$type][] = $idProductList;
        }

        return $mappedProductListIds;
    }

    /**
     * @param array $productListIds
     * @param array $productConcreteCountByProductAbstractIds
     *
     * @return array
     */
    protected function filterProductListIds(array $productListIds, array $productConcreteCountByProductAbstractIds): array
    {
        return array_filter($productListIds, function (array $item) use ($productConcreteCountByProductAbstractIds) {
            if ($item[ProductListRepository::COL_TYPE] === $this->getWhitelistEnumValue()) {
                return true;
            }

            $idProductAbstract = $item[ProductListRepository::COL_ID_PRODUCT_ABSTRACT];

            return $this->isEveryConcreteProductInList(
                $item,
                $productConcreteCountByProductAbstractIds[$idProductAbstract][ProductListRepository::COL_CONCRETE_PRODUCT_COUNT]
            );
        });
    }

    /**
     * @return int
     */
    protected function getWhitelistEnumValue(): int
    {
        return array_flip(
            SpyProductListTableMap::getValueSet(SpyProductListTableMap::COL_TYPE)
        )[SpyProductListTableMap::COL_TYPE_WHITELIST];
    }

    /**
     * @param array $item
     * @param int $totalProductConcreteCount
     *
     * @return bool
     */
    protected function isEveryConcreteProductInList(array $item, int $totalProductConcreteCount): bool
    {
        return $item[ProductListRepository::COL_CONCRETE_PRODUCT_COUNT] === $totalProductConcreteCount;
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return array
     */
    protected function getCategoryProductList(array $productAbstractIds): array
    {
        return $this->productListRepository->getProductListCategory($productAbstractIds);
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return array
     */
    protected function getProductConcreteCountByProductAbstractIds(array $productAbstractIds): array
    {
        return $this->productListRepository->getProductConcreteCountByProductAbstractIds($productAbstractIds);
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return array
     */
    protected function getProductListsByIdProductAbstractIn(array $productAbstractIds): array
    {
        return $this->productListRepository->getProductListsByProductAbstractIds($productAbstractIds);
    }

    /**
     * @param int $idProductAbstract
     *
     * @return int[]
     */
    public function getProductWhitelistIdsByIdProductAbstract(int $idProductAbstract): array
    {
        return $this->productListRepository->getAbstractProductWhitelistIds($idProductAbstract);
    }

    /**
     * @param int $idProductAbstract
     *
     * @return int[]
     */
    public function getCategoryWhitelistIdsByIdProductAbstract(int $idProductAbstract): array
    {
        return $this->productListRepository->getCategoryWhitelistIdsByIdProductAbstract($idProductAbstract);
    }

    /**
     * @param int $idProduct
     *
     * @return int[]
     */
    public function getProductBlacklistIdsByIdProduct(int $idProduct): array
    {
        return $this->productListRepository->getConcreteProductBlacklistIds($idProduct);
    }

    /**
     * @param int $idProduct
     *
     * @return int[]
     */
    public function getProductWhitelistIdsByIdProduct(int $idProduct): array
    {
        return $this->productListRepository->getConcreteProductWhitelistIds($idProduct);
    }

    /**
     * @param string[] $productConcreteSkus
     * @param int[] $blackListIds
     *
     * @return string[]
     */
    public function getProductConcreteSkusInBlacklists(array $productConcreteSkus, array $blackListIds): array
    {
        return $this->productListRepository->getProductConcreteSkusInBlacklists($productConcreteSkus, $blackListIds);
    }

    /**
     * @param string[] $productConcreteSkus
     * @param int[] $whiteListIds
     *
     * @return string[]
     */
    public function getProductConcreteSkusInWhitelists(array $productConcreteSkus, array $whiteListIds): array
    {
        return $this->productListRepository->getProductConcreteSkusInWhitelists($productConcreteSkus, $whiteListIds);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductListTransfer $productListTransfer
     *
     * @return \Generated\Shared\Transfer\ProductListTransfer
     */
    public function getProductListById(ProductListTransfer $productListTransfer): ProductListTransfer
    {
        $productListTransfer->requireIdProductList();

        $productListTransfer = $this->productListRepository
            ->getProductListById($productListTransfer->getIdProductList());

        $productListCategoryRelationTransfer = new ProductListCategoryRelationTransfer();
        $productListCategoryRelationTransfer->setIdProductList($productListTransfer->getIdProductList());
        $productListCategoryRelationTransfer = $this->productListCategoryRelationReader
            ->getProductListCategoryRelation($productListCategoryRelationTransfer);
        $productListTransfer->setProductListCategoryRelation($productListCategoryRelationTransfer);

        $productListProductConcreteRelationTransfer = new ProductListProductConcreteRelationTransfer();
        $productListProductConcreteRelationTransfer->setIdProductList($productListTransfer->getIdProductList());
        $productListProductConcreteRelationTransfer = $this->productListProductConcreteRelationReader
            ->getProductListProductConcreteRelation($productListProductConcreteRelationTransfer);
        $productListTransfer->setProductListProductConcreteRelation($productListProductConcreteRelationTransfer);

        return $productListTransfer;
    }

    /**
     * @param int[] $productListIds
     *
     * @return int[]
     */
    public function getProductAbstractIdsByProductListIds(array $productListIds): array
    {
        return $this->productListRepository->getProductAbstractIdsByProductListIds($productListIds);
    }
}
