<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductStorage\Finder;

use Spryker\Client\ProductStorage\Mapper\ProductStorageDataMapperInterface;
use Spryker\Client\ProductStorage\Storage\ProductAbstractStorageReaderInterface;

class ProductAbstractViewTransferFinder extends ProductViewTransferFinderAbstract
{
    /**
     * @var \Spryker\Client\ProductStorage\Storage\ProductAbstractStorageReaderInterface
     */
    protected $productAbstractStorage;

    /**
     * @param \Spryker\Client\ProductStorage\Storage\ProductAbstractStorageReaderInterface $productAbstractStorage
     * @param \Spryker\Client\ProductStorage\Mapper\ProductStorageDataMapperInterface $productStorageDataMapper
     */
    public function __construct(ProductAbstractStorageReaderInterface $productAbstractStorage, ProductStorageDataMapperInterface $productStorageDataMapper)
    {
        parent::__construct($productStorageDataMapper);
        $this->productAbstractStorage = $productAbstractStorage;
    }

    /**
     * @param int $idProductAbstract
     * @param string $localeName
     *
     * @return array
     */
    protected function getProductStorageData(int $idProductAbstract, string $localeName): array
    {
        return $this->productAbstractStorage->findProductAbstractStorageData($idProductAbstract, $localeName);
    }
}
