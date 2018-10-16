<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPageSearch\Business\ProductConcretePageSearchReader;

use Spryker\Zed\ProductPageSearch\Persistence\ProductPageSearchRepositoryInterface;

class ProductConcretePageSearchReader implements ProductConcretePageSearchReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductPageSearch\Persistence\ProductPageSearchRepositoryInterface
     */
    protected $repository;

    /**
     * @param \Spryker\Zed\ProductPageSearch\Persistence\ProductPageSearchRepositoryInterface $repository
     */
    public function __construct(ProductPageSearchRepositoryInterface $repository)
    {
        $this->repository = $repository;
    }

    /**
     * @param int[] $productIds
     *
     * @return array
     */
    public function getProductConcretePageSearchTransfersByProductIds(array $productIds): array
    {
        return $this->repository->getProductConcretePageSearchTransfers($productIds);
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return array
     */
    public function getProductConcretePageSearchTransfersByProductIdsGrouppedByStoreAndLocale(array $productConcreteIds): array
    {
        $productConcreteSearchPageTransfers = $this->repository->getProductConcretePageSearchTransfers($productConcreteIds);

        return $this->getTransfersGrouppedByStoreAndLocale($productConcreteSearchPageTransfers);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcretePageSearchTransfer[] $productConcretePageSearchTransfers
     *
     * @return array
     */
    protected function getTransfersGrouppedByStoreAndLocale(array $productConcretePageSearchTransfers): array
    {
        $grouppedProductConcretePageSearchTransfers = [];

        foreach ($productConcretePageSearchTransfers as $productConcretePageSearchTransfer) {
            $idProduct = $productConcretePageSearchTransfer->getFkProduct();
            $storeName = $productConcretePageSearchTransfer->getStore();
            $localeName = $productConcretePageSearchTransfer->getLocale();

            $grouppedProductConcretePageSearchTransfers[$idProduct][$storeName][$localeName] = $productConcretePageSearchTransfer;
        }

        return $grouppedProductConcretePageSearchTransfers;
    }
}
