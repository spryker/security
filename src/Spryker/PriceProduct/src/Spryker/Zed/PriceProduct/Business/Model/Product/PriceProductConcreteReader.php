<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProduct\Business\Model\Product;

use Generated\Shared\Transfer\PriceProductCriteriaTransfer;
use Orm\Zed\PriceProduct\Persistence\Map\SpyPriceProductStoreTableMap;
use Orm\Zed\PriceProduct\Persistence\Map\SpyPriceProductTableMap;
use Propel\Runtime\Formatter\ArrayFormatter;
use Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToStoreFacadeInterface;
use Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface;

class PriceProductConcreteReader implements PriceProductConcreteReaderInterface
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
     * @var \Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @param \Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface $priceProductQueryContainer
     * @param \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductMapperInterface $priceProductMapper
     * @param \Spryker\Zed\PriceProduct\Dependency\Facade\PriceProductToStoreFacadeInterface $storeFacade
     */
    public function __construct(
        PriceProductQueryContainerInterface $priceProductQueryContainer,
        PriceProductMapperInterface $priceProductMapper,
        PriceProductToStoreFacadeInterface $storeFacade
    ) {
        $this->priceProductQueryContainer = $priceProductQueryContainer;
        $this->priceProductMapper = $priceProductMapper;
        $this->storeFacade = $storeFacade;
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return bool
     */
    public function hasPriceForProductConcrete($sku, PriceProductCriteriaTransfer $priceProductCriteriaTransfer)
    {
        $prices = $this->findPriceForProductConcrete($sku, $priceProductCriteriaTransfer);
        if (!$prices) {
            return false;
        }

        if ($priceProductCriteriaTransfer->getPriceMode() === $this->priceProductMapper->getNetPriceModeIdentifier()) {
            return $prices[PriceProductQueryContainerInterface::COL_NET_PRICE] !== null;
        }

        return $prices[PriceProductQueryContainerInterface::COL_GROSS_PRICE] !== null;
    }

    /**
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductConcretePricesBySkuForCurrentStore($sku)
    {
        $idStore = $this->storeFacade->getCurrentStore()->getIdStore();

        $productConcretePriceEntities = $this->priceProductQueryContainer
            ->queryPricesForProductConcreteBySkuForStore($sku, $idStore)
            ->find();

        return $this->priceProductMapper->mapPriceProductTransferCollection($productConcretePriceEntities);
    }

    /**
     * @param int $idProductConcrete
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductConcretePricesById($idProductConcrete)
    {
        $productAbstractPriceEntities = $this->priceProductQueryContainer
            ->queryPricesForProductConcreteById($idProductConcrete)
            ->find();

        return $this->priceProductMapper->mapPriceProductTransferCollection($productAbstractPriceEntities);
    }

    /**
     * @param string $sku
     * @param \Generated\Shared\Transfer\PriceProductCriteriaTransfer $priceProductCriteriaTransfer
     *
     * @return array|null
     */
    public function findPriceForProductConcrete($sku, PriceProductCriteriaTransfer $priceProductCriteriaTransfer)
    {
        return $this->priceProductQueryContainer
            ->queryPriceEntityForProductConcrete($sku, $priceProductCriteriaTransfer)
            ->withColumn(SpyPriceProductStoreTableMap::COL_GROSS_PRICE, PriceProductQueryContainerInterface::COL_GROSS_PRICE)
            ->withColumn(SpyPriceProductStoreTableMap::COL_NET_PRICE, PriceProductQueryContainerInterface::COL_NET_PRICE)
            ->setFormatter(ArrayFormatter::class)
            ->findOne();
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
            ->queryPriceEntityForProductConcrete($sku, $priceProductCriteriaTransfer)
            ->select([SpyPriceProductTableMap::COL_ID_PRICE_PRODUCT])
            ->findOne();

        if (!$idPriceProduct) {
            return null;
        }

        return (int)$idPriceProduct;
    }
}
