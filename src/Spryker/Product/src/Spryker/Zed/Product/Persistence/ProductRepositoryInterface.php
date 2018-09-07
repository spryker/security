<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Product\Persistence;

use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;

interface ProductRepositoryInterface
{
    /**
     * @param string $search
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param int $limit
     *
     * @return array
     */
    public function findProductAbstractDataBySkuOrLocalizedName(string $search, LocaleTransfer $localeTransfer, int $limit): array;

    /**
     * @param string $search
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     * @param int $limit
     *
     * @return array
     */
    public function findProductConcreteDataBySkuOrLocalizedName(string $search, LocaleTransfer $localeTransfer, int $limit): array;

    /**
     * @param int $idProductConcrete
     *
     * @return int|null
     */
    public function findProductAbstractIdByConcreteId(int $idProductConcrete): ?int;

    /**
     * @param int $idProductAbstract
     *
     * @return int[]
     */
    public function findProductConcreteIdsByAbstractProductId(int $idProductAbstract): array;

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return bool
     */
    public function isProductConcreteActive(ProductConcreteTransfer $productConcreteTransfer): bool;

    /**
     * @param string[] $skus
     *
     * @return array
     */
    public function getProductConcreteIdsByConcreteSkus(array $skus): array;

    /**
     * @param int[] $productIds
     *
     * @return array
     */
    public function getProductConcreteSkusByConcreteIds(array $productIds): array;

    /**
     * @param int[] $ids
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer[]
     */
    public function findConcreteProductsByIds(array $ids): array;
}
