<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnitType;

use Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer;
use Spryker\Zed\ProductPackagingUnit\Business\Exception\ProductPackagingUnitTypeUniqueViolationException;
use Spryker\Zed\ProductPackagingUnit\Persistence\ProductPackagingUnitEntityManagerInterface;
use Spryker\Zed\ProductPackagingUnit\Persistence\ProductPackagingUnitRepositoryInterface;

class ProductPackagingUnitTypeWriter implements ProductPackagingUnitTypeWriterInterface
{
    protected const ERROR_PRODUCT_PACKAGING_UNIT_TYPE_EXISTS = 'Product packaging unit type was found already for name "%s".';

    protected const PRODUCT_PACKAGING_UNIT_TYPE_KEY = 'packaging_unit_type.%s.name';

    /**
     * @var \Spryker\Zed\ProductPackagingUnit\Persistence\ProductPackagingUnitEntityManagerInterface
     */
    protected $entityManager;

    /**
     * @var \Spryker\Zed\ProductPackagingUnit\Persistence\ProductPackagingUnitRepositoryInterface
     */
    protected $repository;

    /**
     * @var \Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnitType\ProductPackagingUnitTypeTranslationWriterInterface
     */
    protected $translationWriter;

    /**
     * @var \Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnitType\ProductPackagingUnitTypeKeyGeneratorInterface
     */
    protected $productPackagingUnitTypeKeyGenerator;

    /**
     * @param \Spryker\Zed\ProductPackagingUnit\Persistence\ProductPackagingUnitEntityManagerInterface $entityManager
     * @param \Spryker\Zed\ProductPackagingUnit\Persistence\ProductPackagingUnitRepositoryInterface $repository
     * @param \Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnitType\ProductPackagingUnitTypeTranslationWriterInterface $translationWriter
     * @param \Spryker\Zed\ProductPackagingUnit\Business\Model\ProductPackagingUnitType\ProductPackagingUnitTypeKeyGeneratorInterface $productPackagingUnitTypeGroupKeyGenerator
     */
    public function __construct(
        ProductPackagingUnitEntityManagerInterface $entityManager,
        ProductPackagingUnitRepositoryInterface $repository,
        ProductPackagingUnitTypeTranslationWriterInterface $translationWriter,
        ProductPackagingUnitTypeKeyGeneratorInterface $productPackagingUnitTypeGroupKeyGenerator
    ) {
        $this->entityManager = $entityManager;
        $this->repository = $repository;
        $this->translationWriter = $translationWriter;
        $this->productPackagingUnitTypeKeyGenerator = $productPackagingUnitTypeGroupKeyGenerator;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
     *
     * @throws \Spryker\Zed\ProductPackagingUnit\Business\Exception\ProductPackagingUnitTypeUniqueViolationException
     *
     * @return \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer
     */
    public function createProductPackagingUnitType(
        ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
    ): ProductPackagingUnitTypeTransfer {

        $this->productPackagingUnitTypeKeyGenerator->generateProductPackagingUnitTypeKey($productPackagingUnitTypeTransfer);

        $productPackagingUnitTypeTransfer->requireName();

        if ($this->isUniqueForCreate($productPackagingUnitTypeTransfer)) {
            $this->translationWriter->saveTranslations($productPackagingUnitTypeTransfer);

            return $this->entityManager->saveProductPackagingUnitType($productPackagingUnitTypeTransfer);
        }

        throw new ProductPackagingUnitTypeUniqueViolationException(sprintf(
            static::ERROR_PRODUCT_PACKAGING_UNIT_TYPE_EXISTS,
            $productPackagingUnitTypeTransfer->getName()
        ));
    }

    /**
     * @param \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
     *
     * @return bool
     */
    protected function isUniqueForCreate(
        ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
    ): bool {
        return $this->repository->findProductPackagingUnitTypeByName($productPackagingUnitTypeTransfer->getName()) === null;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
     *
     * @throws \Spryker\Zed\ProductPackagingUnit\Business\Exception\ProductPackagingUnitTypeUniqueViolationException
     *
     * @return \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer
     */
    public function updateProductPackagingUnitType(
        ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
    ): ProductPackagingUnitTypeTransfer {
        $productPackagingUnitTypeTransfer->requireIdProductPackagingUnitType();

        if ($this->isUniqueForUpdate($productPackagingUnitTypeTransfer)) {
            $this->translationWriter->saveTranslations($productPackagingUnitTypeTransfer);

            return $this->entityManager->saveProductPackagingUnitType($productPackagingUnitTypeTransfer);
        }

        throw new ProductPackagingUnitTypeUniqueViolationException(sprintf(
            static::ERROR_PRODUCT_PACKAGING_UNIT_TYPE_EXISTS,
            $productPackagingUnitTypeTransfer->getName()
        ));
    }

    /**
     * @param \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
     *
     * @return bool
     */
    protected function isUniqueForUpdate(
        ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
    ): bool {
        $existingProductPackagingUnitTypeTransfer = $this->repository->findProductPackagingUnitTypeByName($productPackagingUnitTypeTransfer->getName());

        return $existingProductPackagingUnitTypeTransfer === null ||
            $productPackagingUnitTypeTransfer->getIdProductPackagingUnitType() === $existingProductPackagingUnitTypeTransfer->getIdProductPackagingUnitType();
    }

    /**
     * @param \Generated\Shared\Transfer\ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
     *
     * @return bool
     */
    public function deleteProductPackagingUnitType(
        ProductPackagingUnitTypeTransfer $productPackagingUnitTypeTransfer
    ): bool {
        $productPackagingUnitTypeTransfer->requireIdProductPackagingUnitType();

        $countProductPackagingUnitsByTypeId = $this->repository
            ->countProductPackagingUnitsByTypeId(
                $productPackagingUnitTypeTransfer->getIdProductPackagingUnitType()
            );

        if ($countProductPackagingUnitsByTypeId <= 0) {
            $this->translationWriter->deleteTranslations($productPackagingUnitTypeTransfer);

            return $this->entityManager->deleteProductPackagingUnitType($productPackagingUnitTypeTransfer);
        }

        return false;
    }
}
