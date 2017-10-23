<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOption\Business\OptionGroup;

use Generated\Shared\Transfer\ProductOptionTransfer;
use Orm\Zed\ProductOption\Persistence\SpyProductOptionValue;
use Spryker\Zed\ProductOption\Business\Exception\ProductOptionNotFoundException;
use Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface;

class ProductOptionValueReader implements ProductOptionValueReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface
     */
    protected $productOptionQueryContainer;

    /**
     * @param \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface $productOptionQueryContainer
     */
    public function __construct(ProductOptionQueryContainerInterface $productOptionQueryContainer)
    {
        $this->productOptionQueryContainer = $productOptionQueryContainer;
    }

    /**
     * @param int $idProductOptionValue
     *
     * @throws \Spryker\Zed\ProductOption\Business\Exception\ProductOptionNotFoundException
     *
     * @return \Generated\Shared\Transfer\ProductOptionTransfer
     */
    public function getProductOption($idProductOptionValue)
    {
        $productOptionValueEntity = $this->getOptionValueById($idProductOptionValue);

        if (!$productOptionValueEntity) {
            throw new ProductOptionNotFoundException(
                sprintf('Product option with id "%d" not found in persistence.', $idProductOptionValue)
            );
        }

        return $this->hydrateProductOptionTransfer($productOptionValueEntity);
    }

    /**
     * @param \Orm\Zed\ProductOption\Persistence\SpyProductOptionValue $productOptionValueEntity
     *
     * @return \Generated\Shared\Transfer\ProductOptionTransfer
     */
    protected function hydrateProductOptionTransfer(SpyProductOptionValue $productOptionValueEntity)
    {
        $productOptionTransfer = new ProductOptionTransfer();
        $productOptionTransfer->fromArray($productOptionValueEntity->toArray(), true);
        $productOptionTransfer->setGroupName($productOptionValueEntity->getSpyProductOptionGroup()->getName());
        $productOptionTransfer->setUnitGrossPrice($productOptionValueEntity->getPrice());

        return $productOptionTransfer;
    }

    /**
     * @param int $idProductOptionValue
     *
     * @return \Orm\Zed\ProductOption\Persistence\SpyProductOptionValue
     */
    protected function getOptionValueById($idProductOptionValue)
    {
        $productOptionValueEntity = $this->productOptionQueryContainer
            ->queryProductOptionByValueId((int)$idProductOptionValue)
            ->findOne();

        return $productOptionValueEntity;
    }
}
