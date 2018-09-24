<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Product;

use Generated\Shared\Transfer\ProductConcreteTransfer;

interface ProductClientInterface
{
    /**
     * Specification:
     * - Reads abstract product data from locale specific Storage.
     *
     * @api
     *
     * @param int $idProductAbstract
     * @param string $locale
     *
     * @return array
     */
    public function getProductAbstractFromStorageById($idProductAbstract, $locale);

    /**
     * Specification:
     * - Reads abstract product data from Storage.
     * - Selects Storage using current shop locale.
     *
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return array
     */
    public function getProductAbstractFromStorageByIdForCurrentLocale($idProductAbstract);

    /**
     * Specification:
     * - Reads attribute map from Storage.
     * - Selects Storage using current shop locale.
     *
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return array
     */
    public function getAttributeMapByIdProductAbstractForCurrentLocale($idProductAbstract);

    /**
     * Specification:
     * - Reads attribute map from locale specific Storage.
     *
     * @api
     *
     * @param int $idProductAbstract
     * @param string $locale
     *
     * @return array
     */
    public function getAttributeMapByIdAndLocale($idProductAbstract, $locale);

    /**
     * Specification:
     * - Reads concrete product data from Storage.
     * - Selects Storage using current shop locale.
     *
     * @api
     *
     * @param int $idProductConcrete
     *
     * @return array
     */
    public function getProductConcreteByIdForCurrentLocale($idProductConcrete);

    /**
     * Specification:
     * - Reads concrete product data from locale specific Storage.
     *
     * @api
     *
     * @param int $idProductConcrete
     * @param string $locale
     *
     * @return array
     */
    public function getProductConcreteByIdAndLocale($idProductConcrete, $locale);

    /**
     * Specification:
     * - Reads concrete product data based on provided product concrete id collection.
     *
     * @api
     *
     * @param array $idProductConcreteCollection
     *
     * @return \Generated\Shared\Transfer\StorageProductTransfer[]
     */
    public function getProductConcreteCollection(array $idProductConcreteCollection);

    /**
     * Specification
     * - Finds concrete product ID by given SKU.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function findProductConcreteIdBySku(ProductConcreteTransfer $productConcreteTransfer): ProductConcreteTransfer;
}
