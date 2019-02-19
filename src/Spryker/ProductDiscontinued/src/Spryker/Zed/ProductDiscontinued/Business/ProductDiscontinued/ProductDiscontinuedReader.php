<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinued\Business\ProductDiscontinued;

use Generated\Shared\Transfer\ProductDiscontinuedCollectionTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedCriteriaFilterTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer;
use Generated\Shared\Transfer\ProductDiscontinuedTransfer;
use Spryker\Zed\ProductDiscontinued\Persistence\ProductDiscontinuedRepositoryInterface;

class ProductDiscontinuedReader implements ProductDiscontinuedReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductDiscontinued\Persistence\ProductDiscontinuedRepositoryInterface
     */
    protected $productDiscontinuedRepository;

    /**
     * @param \Spryker\Zed\ProductDiscontinued\Persistence\ProductDiscontinuedRepositoryInterface $productDiscontinuedRepository
     */
    public function __construct(ProductDiscontinuedRepositoryInterface $productDiscontinuedRepository)
    {
        $this->productDiscontinuedRepository = $productDiscontinuedRepository;
    }

    /**
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedResponseTransfer
     */
    public function findProductDiscontinuedByProductId(int $idProduct): ProductDiscontinuedResponseTransfer
    {
        $productDiscontinuedTransfer = (new ProductDiscontinuedTransfer())
            ->setFkProduct($idProduct);
        $productDiscontinuedTransfer = $this->productDiscontinuedRepository->findProductDiscontinuedByProductId(
            $productDiscontinuedTransfer
        );

        return (new ProductDiscontinuedResponseTransfer())
            ->setProductDiscontinued($productDiscontinuedTransfer)
            ->setIsSuccessful((bool)$productDiscontinuedTransfer);
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return bool
     */
    public function isAnyProductConcreteDiscontinued(array $productConcreteIds): bool
    {
        return $this->productDiscontinuedRepository->isAnyProductConcreteDiscontinued($productConcreteIds);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductDiscontinuedCriteriaFilterTransfer $criteriaFilterTransfer
     *
     * @return \Generated\Shared\Transfer\ProductDiscontinuedCollectionTransfer
     */
    public function findProductDiscontinuedCollection(
        ProductDiscontinuedCriteriaFilterTransfer $criteriaFilterTransfer
    ): ProductDiscontinuedCollectionTransfer {
        return $this->productDiscontinuedRepository->findProductDiscontinuedCollection($criteriaFilterTransfer);
    }

    /**
     * @param int[] $productIds
     *
     * @return bool
     */
    public function areAllConcreteProductsDiscontinued(array $productIds): bool
    {
        return $this->productDiscontinuedRepository->areAllConcreteProductsDiscontinued($productIds);
    }

    /**
     * @return int[]
     */
    public function findProductAbstractIdsWithDiscontinuedConcrete(): array
    {
        return $this->productDiscontinuedRepository->findProductAbstractIdsWithDiscontinuedConcrete();
    }
}
