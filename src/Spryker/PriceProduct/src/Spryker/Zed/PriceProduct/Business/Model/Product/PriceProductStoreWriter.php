<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProduct\Business\Model\Product;

use Generated\Shared\Transfer\MoneyValueTransfer;
use Generated\Shared\Transfer\PriceProductTransfer;
use Orm\Zed\PriceProduct\Persistence\SpyPriceProductStore;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;
use Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductStoreWriter\PriceProductStoreWriterPluginExecutorInterface;
use Spryker\Zed\PriceProduct\Persistence\PriceProductEntityManagerInterface;
use Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface;
use Spryker\Zed\PriceProduct\Persistence\PriceProductRepositoryInterface;

class PriceProductStoreWriter implements PriceProductStoreWriterInterface
{
    use TransactionTrait;

    /**
     * @var \Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface
     */
    protected $priceProductQueryContainer;

    /**
     * @var \Spryker\Zed\PriceProduct\Persistence\PriceProductEntityManagerInterface
     */
    protected $priceProductEntityManager;

    /**
     * @var \Spryker\Zed\PriceProduct\Persistence\PriceProductRepositoryInterface
     */
    protected $priceProductRepository;

    /**
     * @var \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductStoreWriter\PriceProductStoreWriterPluginExecutorInterface
     */
    protected $priceProductStoreWriterPluginExecutor;

    /**
     * @param \Spryker\Zed\PriceProduct\Persistence\PriceProductQueryContainerInterface $priceProductQueryContainer
     * @param \Spryker\Zed\PriceProduct\Persistence\PriceProductEntityManagerInterface $priceProductEntityManager
     * @param \Spryker\Zed\PriceProduct\Persistence\PriceProductRepositoryInterface $priceProductRepository
     * @param \Spryker\Zed\PriceProduct\Business\Model\Product\PriceProductStoreWriter\PriceProductStoreWriterPluginExecutorInterface $priceProductStoreWriterPluginExecutor
     */
    public function __construct(
        PriceProductQueryContainerInterface $priceProductQueryContainer,
        PriceProductEntityManagerInterface $priceProductEntityManager,
        PriceProductRepositoryInterface $priceProductRepository,
        PriceProductStoreWriterPluginExecutorInterface $priceProductStoreWriterPluginExecutor
    ) {
        $this->priceProductQueryContainer = $priceProductQueryContainer;
        $this->priceProductEntityManager = $priceProductEntityManager;
        $this->priceProductRepository = $priceProductRepository;
        $this->priceProductStoreWriterPluginExecutor = $priceProductStoreWriterPluginExecutor;
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $priceProductTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer
     */
    public function persistPriceProductStore(PriceProductTransfer $priceProductTransfer): PriceProductTransfer
    {
        $priceProductTransfer->requireMoneyValue();

        $moneyValueTransfer = $priceProductTransfer->getMoneyValue();

        $moneyValueTransfer
            ->requireFkCurrency()
            ->requireFkStore();

        $priceProduceStoreEntity = $this->findPriceProductStoreEntity(
            $priceProductTransfer,
            $moneyValueTransfer
        );

        $priceProduceStoreEntity->fromArray($moneyValueTransfer->toArray());

        $priceProduceStoreEntity
            ->setGrossPrice($moneyValueTransfer->getGrossAmount())
            ->setNetPrice($moneyValueTransfer->getNetAmount())
            ->setFkPriceProduct($priceProductTransfer->getIdPriceProduct())
            ->save();

        $moneyValueTransfer->setIdEntity($priceProduceStoreEntity->getIdPriceProductStore());

        $this->priceProductStoreWriterPluginExecutor->runPriceDimensionSaverPlugins($priceProductTransfer);

        return $priceProductTransfer;
    }

    /**
     * @return void
     */
    public function deleteOrphanPriceProductStoreEntities(): void
    {
        $orphanPriceProductStoreEntities = $this->priceProductRepository->findOrphanPriceProductStoreEntities();

        if (count($orphanPriceProductStoreEntities) === 0) {
            return;
        }

        $this->getTransactionHandler()->handleTransaction(function () use ($orphanPriceProductStoreEntities) {
            $this->doDeleteOrphanPriceProductStoreEntities($orphanPriceProductStoreEntities);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\SpyPriceProductStoreEntityTransfer[] $priceProductStoreEntityTransfers
     *
     * @return void
     */
    protected function doDeleteOrphanPriceProductStoreEntities(array $priceProductStoreEntityTransfers): void
    {
        foreach ($priceProductStoreEntityTransfers as $priceProductStoreEntityTransfer) {
            $idPriceProductStore = $priceProductStoreEntityTransfer->getIdPriceProductStore();

            $this->priceProductStoreWriterPluginExecutor->runPriceProductStorePreDeletePlugins($idPriceProductStore);
            $this->priceProductEntityManager->deletePriceProductStore($idPriceProductStore);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $priceProductTransfer
     * @param \Generated\Shared\Transfer\MoneyValueTransfer $moneyValueTransfer
     *
     * @return \Orm\Zed\PriceProduct\Persistence\SpyPriceProductStore
     */
    protected function findPriceProductStoreEntity(
        PriceProductTransfer $priceProductTransfer,
        MoneyValueTransfer $moneyValueTransfer
    ): SpyPriceProductStore {

        return $this->priceProductQueryContainer
            ->queryPriceProductStoreByProductCurrencyStore(
                $priceProductTransfer->getIdPriceProduct(),
                $moneyValueTransfer->getFkCurrency(),
                $moneyValueTransfer->getFkStore()
            )
            ->filterByNetPrice($moneyValueTransfer->getNetAmount())
            ->filterByGrossPrice($moneyValueTransfer->getGrossAmount())
            ->filterByPriceDataChecksum($moneyValueTransfer->getPriceDataChecksum())
            ->findOneOrCreate();
    }
}
