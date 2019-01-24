<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductList\Business\ProductList;

use Generated\Shared\Transfer\ProductListCategoryRelationTransfer;
use Generated\Shared\Transfer\ProductListProductConcreteRelationTransfer;
use Generated\Shared\Transfer\ProductListTransfer;
use Orm\Zed\ProductList\Persistence\Map\SpyProductListTableMap;
use Spryker\Zed\ProductList\Business\ProductListCategoryRelation\ProductListCategoryRelationReaderInterface;
use Spryker\Zed\ProductList\Business\ProductListProductConcreteRelation\ProductListProductConcreteRelationReaderInterface;
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
        return array_unique(
            array_merge(
                $this->productListRepository->getConcreteProductListIdsForType(
                    $idProduct,
                    SpyProductListTableMap::COL_TYPE_BLACKLIST
                ),
                $this->productListRepository->getProductConcreteProductListIdsRelatedToCategoriesForType(
                    $idProduct,
                    SpyProductListTableMap::COL_TYPE_BLACKLIST
                )
            )
        );
    }

    /**
     * @param int $idProduct
     *
     * @return int[]
     */
    public function getProductWhitelistIdsByIdProduct(int $idProduct): array
    {
        return array_unique(
            array_merge(
                $this->productListRepository->getConcreteProductListIdsForType(
                    $idProduct,
                    SpyProductListTableMap::COL_TYPE_WHITELIST
                ),
                $this->productListRepository->getProductConcreteProductListIdsRelatedToCategoriesForType(
                    $idProduct,
                    SpyProductListTableMap::COL_TYPE_WHITELIST
                )
            )
        );
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
        return array_unique(
            array_merge(
                $this->productListRepository->getProductAbstractIdsRelatedToProductConcrete($productListIds),
                $this->productListRepository->getProductAbstractIdsRelatedToCategories($productListIds)
            )
        );
    }

    /**
     * @param int[] $productListIds
     *
     * @return int[]
     */
    public function getProductConcreteIdsByProductListIds(array $productListIds): array
    {
        return array_unique(
            array_merge(
                $this->productListRepository->getProductConcreteIdsRelatedToProductLists($productListIds),
                $this->productListRepository->getProductConcreteIdsRelatedToProductListsCategories($productListIds)
            )
        );
    }
}
