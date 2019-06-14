<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProduct\Business\Model\Product;

use Generated\Shared\Transfer\PriceProductCriteriaTransfer;
use Generated\Shared\Transfer\PriceProductDimensionTransfer;
use Generated\Shared\Transfer\PriceProductTransfer;
use Orm\Zed\PriceProduct\Persistence\Map\SpyPriceProductTableMap;
use Spryker\Service\PriceProduct\PriceProductServiceInterface;
use Spryker\Zed\PriceProduct\Business\Model\PriceProductCriteriaBuilderInterface;
use Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductReader\PriceProductReaderPluginExecutorInterface;
use Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToProductFacadeInterface;
use Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToStoreFacadeInterface;
use Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface;
use Spryker\Zed\PriceProduct\Persistence\PriceProductRepositoryInterface;

class PriceProductAbstractReader implements PriceProductAbstractReaderInterface
{
    /**
     * @var \Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface;
     */
    protected $priceProductQueryContainer;

    /**
     * @var \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductMapperInterface
     */
    protected $priceProductMapper;

    /**
     * @var \Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToProductFacadeInterface
     */
    protected $productFacade;

    /**
     * @var \Spryker\Zed\PriceProduct\Business\Model\PriceProductCriteriaBuilderInterface
     */
    protected $priceProductCriteriaBuilder;

    /**
     * @var \Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\PriceProduct\Persistence\PriceProductRepositoryInterface
     */
    protected $priceProductRepository;

    /**
     * @var \Spryker\Service\PriceProduct\PriceProductServiceInterface
     */
    protected $priceProductService;

    /**
     * @var \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductExpanderInterface
     */
    protected $priceProductExpander;

    /**
     * @var \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductReader\PriceProductReaderPluginExecutorInterface
     */
    protected $pluginExecutor;

    /**
     * @param \Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface $priceProductQueryContainer
     * @param \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductMapperInterface $priceProductMapper
     * @param \Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToProductFacadeInterface $productFacade
     * @param \Spryker\Zed\PriceProduct\Business\Model\PriceProductCriteriaBuilderInterface $priceProductCriteriaBuilder
     * @param \Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\PriceProduct\Persistence\PriceProductRepositoryInterface $priceProductRepository
     * @param \Spryker\Service\PriceProduct\PriceProductServiceInterface $priceProductService
     * @param \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductExpanderInterface $priceProductExpander
     * @param \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductReader\PriceProductReaderPluginExecutorInterface $pluginExecutor
     */
    public function __construct(
        PriceProductQueryContainerInterface $priceProductQueryContainer,
        PriceProductMapperInterface $priceProductMapper,
        PriceProductToProductFacadeInterface $productFacade,
        PriceProductCriteriaBuilderInterface $priceProductCriteriaBuilder,
        PriceProductToStoreFacadeInterface $storeFacade,
        PriceProductRepositoryInterface $priceProductRepository,
        PriceProductServiceInterface $priceProductService,
        PriceProductExpanderInterface $priceProductExpander,
        PriceProductReaderPluginExecutorInterface $pluginExecutor
    ) {
        $this->priceProductQueryContainer = $priceProductQueryContainer;
        $this->priceProductMapper = $priceProductMapper;
        $this->productFacade = $productFacade;
        $this->priceProductCriteriaBuilder = $priceProductCriteriaBuilder;
        $this->storeFacade = $storeFacade;
        $this->priceProductRepository = $priceProductRepository;
        $this->priceProductService = $priceProductService;
        $this->priceProductExpander = $priceProductExpander;
        $this->pluginExecutor = $pluginExecutor;
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return bool
     */
    public function hasPriceForProductAbstract($sku, PriceProductCriteriaTransfer $priceProductCriteriaTransfer): bool
    {
        return $this->findPriceForProductAbstract($sku, $priceProductCriteriaTransfer) !== null;
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductDimensionTransfer $priceProductDimensionTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPricesBySkuForCurrentStore(
        string $sku,
        PriceProductDimensionTransfer $priceProductDimensionTransfer
    ): array {

        $abstractSku = $this->findAbstractSku($sku);

        $idStore = $this->storeFacade->getCurrentStore()->getIdStore();

        $priceProductCriteriaTransfer = (new PriceProductCriteriaTransfer())
            ->setIdStore($idStore)
            ->setPriceDimension($priceProductDimensionTransfer);

        $priceProductStoreEntities = $this->priceProductRepository
            ->findProductAbstractPricesBySkuAndCriteria($abstractSku, $priceProductCriteriaTransfer);

        $priceProductTransfers = $this->priceProductMapper->mapPriceProductStoreEntitiesToPriceProductTransfers(
            $priceProductStoreEntities
        );

        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);
        $priceProductTransfers = $this->pluginExecutor->executePriceExtractorPluginsForProductAbstract($priceProductTransfers);

        return $priceProductTransfers;
    }

    /**
     * @param string $sku
     *
     * @return string
     */
    public function findAbstractSku($sku)
    {
        $abstractSku = $sku;
        if ($this->productFacade->hasProductConcrete($sku)) {
            $abstractSku = $this->productFacade->getAbstractSkuFromProductConcrete($sku);
        }

        return $abstractSku;
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer|null
     */
    public function findPriceForProductAbstract(string $sku, PriceProductCriteriaTransfer $priceProductCriteriaTransfer): ?PriceProductTransfer
    {
        $priceProductTransfers = $this->findProductAbstractPricesBySkuAndCriteria($sku, $priceProductCriteriaTransfer);

        return $this->priceProductService->resolveProductPriceByPriceProductCriteria($priceProductTransfers, $priceProductCriteriaTransfer);
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPricesBySkuAndCriteria(string $sku, PriceProductCriteriaTransfer $priceProductCriteriaTransfer): array
    {
        $priceProductStoreEntities = $this->priceProductRepository
            ->findProductAbstractPricesBySkuAndCriteria($sku, $priceProductCriteriaTransfer);

        $priceProductTransfers = $this->priceProductMapper->mapPriceProductStoreEntitiesToPriceProductTransfers(
            $priceProductStoreEntities
        );

        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);
        $priceProductTransfers = $this->pluginExecutor->executePriceExtractorPluginsForProductAbstract($priceProductTransfers);

        return $priceProductTransfers;
    }

    /**
     * @param int $idProductAbstract
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer|null $priceProductCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPricesById(int $idProductAbstract, ?PriceProductCriteriaTransfer $priceProductCriteriaTransfer = null): array
    {
        if (!$priceProductCriteriaTransfer) {
            $priceProductCriteriaTransfer = new PriceProductCriteriaTransfer();
        }

        $priceProductEntities = $this->priceProductRepository
            ->findProductAbstractPricesByIdAndCriteria($idProductAbstract, $priceProductCriteriaTransfer);

        $priceProductTransfers = $this->priceProductMapper->mapPriceProductStoreEntitiesToPriceProductTransfers($priceProductEntities);
        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);
        $priceProductTransfers = $this->pluginExecutor->executePriceExtractorPluginsForProductAbstract($priceProductTransfers);

        return $priceProductTransfers;
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return int|null
     */
    public function findPriceProductId($sku, PriceProductCriteriaTransfer $priceProductCriteriaTransfer)
    {
        $idPriceProduct = $this->priceProductQueryContainer
            ->queryPriceEntityForProductAbstract($sku, $priceProductCriteriaTransfer)
            ->select([SpyPriceProductTableMap::COL_ID_PRICE_PRODUCT])
            ->findOne();

        if (!$idPriceProduct) {
            return null;
        }

        return (int)$idPriceProduct;
    }

    /**
     * @param int $idAbstractProduct
     * @param string|null $priceTypeName
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer|null
     */
    public function findProductAbstractPrice($idAbstractProduct, $priceTypeName = null)
    {
        $priceProductCriteriaTransfer = $this->priceProductCriteriaBuilder
            ->buildCriteriaWithDefaultValues($priceTypeName);

        $priceProductStoreEntity = $this->priceProductQueryContainer
            ->queryPriceEntityForProductAbstractById($idAbstractProduct, $priceProductCriteriaTransfer)
            ->findOne();

        if (!$priceProductStoreEntity) {
            return null;
        }

        return $this->priceProductMapper->mapProductPriceTransfer(
            $priceProductStoreEntity,
            $priceProductStoreEntity->getPriceProduct()
        );
    }

    /**
     * @param int $idProductAbstract
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer|null $priceProductCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPricesWithoutPriceExtraction(int $idProductAbstract, ?PriceProductCriteriaTransfer $priceProductCriteriaTransfer = null): array
    {
        if (!$priceProductCriteriaTransfer) {
            $priceProductCriteriaTransfer = new PriceProductCriteriaTransfer();
        }

        $priceProductEntities = $this->priceProductRepository
            ->findProductAbstractPricesByIdAndCriteria($idProductAbstract, $priceProductCriteriaTransfer);
        $priceProductTransfers = $this->priceProductMapper->mapPriceProductStoreEntitiesToPriceProductTransfers($priceProductEntities);
        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);

        return $priceProductTransfers;
    }

    /**
     * @param array $productAbstractIds
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPricesWithoutPriceExtractionByIdProductAbstractIn(array $productAbstractIds): array
    {
        $priceProductEntities = $this->priceProductRepository->findProductAbstractPricesByIdIn($productAbstractIds);
        $priceProductTransfers = $this->priceProductMapper->mapPriceProductStoreEntitiesToPriceProductTransfers($priceProductEntities);
        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);

        return $priceProductTransfers;
    }

    /**
     * @param int[] $productAbstractIds
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer|null $priceProductCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPricesWithoutPriceExtractionByProductAbstractIdsAndCriteria(array $productAbstractIds, ?PriceProductCriteriaTransfer $priceProductCriteriaTransfer = null): array
    {
        if (!$priceProductCriteriaTransfer) {
            $priceProductCriteriaTransfer = new PriceProductCriteriaTransfer();
        }

        $priceProductEntities = $this->priceProductRepository->findProductAbstractPricesByIdInAndCriteria($productAbstractIds, $priceProductCriteriaTransfer);
        $priceProductTransfers = $this->priceProductMapper->mapPriceProductStoreEntitiesToPriceProductTransfers($priceProductEntities);
        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);

        return $priceProductTransfers;
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $priceProductTransfer
     *
     * @return int|null
     */
    public function findIdProductAbstractForPriceProduct(PriceProductTransfer $priceProductTransfer): ?int
    {
        if ($priceProductTransfer->getIdProduct()) {
            return $this->productFacade->getProductAbstractIdByConcreteId($priceProductTransfer->getIdProduct());
        }

        if ($priceProductTransfer->getSkuProduct()) {
            return $this->productFacade->getProductAbstractIdByConcreteSku($priceProductTransfer->getSkuProduct());
        }

        return null;
    }

    /**
     * @param string[] $concreteSkus
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function getProductAbstractPricesByConcreteSkusAndCriteria(array $concreteSkus, PriceProductCriteriaTransfer $priceProductCriteriaTransfer): array
    {
        $priceProductTransfers = $this->priceProductRepository
            ->getProductAbstractPricesByConcreteSkusAndCriteria($concreteSkus, $priceProductCriteriaTransfer);
        $priceProductTransfers = $this->priceProductExpander->expandPriceProductTransfers($priceProductTransfers);
        $priceProductTransfers = $this->pluginExecutor->executePriceExtractorPluginsForProductConcrete($priceProductTransfers);

        return $this->indexPriceProductTransferByProductSku($priceProductTransfers);
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer[] $priceProductTransfers
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[][]
     */
    protected function indexPriceProductTransferByProductSku(array $priceProductTransfers): array
    {
        $indexedPriceProductTransfers = [];
        foreach ( $priceProductTransfers as $priceProductTransfer) {
            $indexedPriceProductTransfers[$priceProductTransfer->getSkuProduct()][] = $priceProductTransfer;
        }

        return $indexedPriceProductTransfers;
    }
}
