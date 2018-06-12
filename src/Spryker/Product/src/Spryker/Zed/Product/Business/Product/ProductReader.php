<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Product\Business\Product;

use Spryker\Zed\Product\Dependency\Facade\ProductToLocaleInterface;
use Spryker\Zed\Product\Persistence\ProductRepositoryInterface;

class ProductReader implements ProductReaderInterface
{
    /**
     * @var \Spryker\Zed\Product\Dependency\Facade\ProductToLocaleInterface
     */
    protected $localeFacade;

    /**
     * @var \Spryker\Zed\Product\Persistence\ProductRepositoryInterface
     */
    protected $productRepository;

    /**
     * @param \Spryker\Zed\Product\Dependency\Facade\ProductToLocaleInterface $localeFacade
     * @param \Spryker\Zed\Product\Persistence\ProductRepositoryInterface $productRepository
     */
    public function __construct(
        ProductToLocaleInterface $localeFacade,
        ProductRepositoryInterface $productRepository
    ) {
        $this->localeFacade = $localeFacade;
        $this->productRepository = $productRepository;
    }

    /**
     * @param string $sku
     * @param null|int $limit
     *
     * @return array
     */
    public function getProductAbstractDataBySku(string $sku, ?int $limit = null): array
    {
        return $this->productRepository
            ->getProductAbstractDataBySku($sku, $limit);
    }

    /**
     * @param string $localizedName
     * @param null|int $limit
     *
     * @return array
     */
    public function getProductAbstractDataByLocalizedName(string $localizedName, ?int $limit = null): array
    {
        return $this->productRepository
            ->getProductAbstractDataByLocalizedName(
                $this->localeFacade->getCurrentLocale(),
                $localizedName,
                $limit
            );
    }

    /**
     * @param string $sku
     * @param null|int $limit
     *
     * @return array
     */
    public function getProductConcreteDataBySku(string $sku, ?int $limit = null): array
    {
        return $this->productRepository
            ->getProductConcreteDataBySku($sku, $limit);
    }

    /**
     * @param string $localizedName
     * @param null|int $limit
     *
     * @return array
     */
    public function getProductConcreteDataByLocalizedName(string $localizedName, ?int $limit = null): array
    {
        return $this->productRepository
            ->getProductConcreteDataByLocalizedName(
                $this->localeFacade->getCurrentLocale(),
                $localizedName,
                $limit
            );
    }
}
