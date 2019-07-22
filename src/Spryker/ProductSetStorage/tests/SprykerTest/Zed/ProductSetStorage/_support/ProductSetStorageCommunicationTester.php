<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\ProductSetStorage;

use ArrayObject;
use Codeception\Actor;
use Generated\Shared\DataBuilder\LocalizedProductSetBuilder;
use Generated\Shared\DataBuilder\ProductImageBuilder;
use Generated\Shared\DataBuilder\ProductSetBuilder;
use Generated\Shared\Transfer\ProductImageTransfer;
use Generated\Shared\Transfer\ProductSetTransfer;
use Orm\Zed\ProductImage\Persistence\SpyProductImageSetToProductImageQuery;
use Orm\Zed\ProductSetStorage\Persistence\SpyProductSetStorageQuery;
use Spryker\Zed\ProductSet\Business\ProductSetFacadeInterface;

/**
 * Inherited Methods
 * @method void wantToTest($text)
 * @method void wantTo($text)
 * @method void execute($callable)
 * @method void expectTo($prediction)
 * @method void expect($prediction)
 * @method void amGoingTo($argumentation)
 * @method void am($role)
 * @method void lookForwardTo($achieveValue)
 * @method void comment($description)
 * @method \Codeception\Lib\Friend haveFriend($name, $actorClass = NULL)
 *
 * @SuppressWarnings(PHPMD)
 */
class ProductSetStorageCommunicationTester extends Actor
{
    use _generated\ProductSetStorageCommunicationTesterActions;

   /**
    * Define custom actions here
    */

    public const PARAM_PROJECT = 'PROJECT';

    public const PROJECT_SUITE = 'suite';

    /**
     * @return bool
     */
    public function isSuiteProject()
    {
        if (getenv(static::PARAM_PROJECT) === static::PROJECT_SUITE) {
            return true;
        }

        return false;
    }

    /**
     * @param int $productSetAmount
     *
     * @return \Generated\Shared\Transfer\ProductSetTransfer[]
     */
    public function createProductSets(int $productSetAmount): array
    {
        $productSetTransfers = [];
        for ($i = 0; $i < $productSetAmount; $i++) {
            $productSetTransfers[] = $this->haveProductSet();
        }

        return $productSetTransfers;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductImageTransfer[] $productImageTransfers
     *
     * @return \Generated\Shared\Transfer\ProductSetTransfer
     */
    public function createProductSetWithProductImages(array $productImageTransfers): ProductSetTransfer
    {
        $localizedProductSetTransfer = (new LocalizedProductSetBuilder())->withProductSetData()->build();
        $localizedProductSetTransfer->setLocale($this->haveLocale());

        $productAbstractTransfer = $this->haveProductAbstract();

        $productSetTransfer = (new ProductSetBuilder())->withImageSet()->build();
        $productSetTransfer->addLocalizedData($localizedProductSetTransfer);
        $productSetTransfer->setIdProductAbstracts([$productAbstractTransfer->getIdProductAbstract()]);
        $productSetTransfer->getImageSets()[0]->setProductImages(new ArrayObject($productImageTransfers));

        return $this->getProductSetFacade()->createProductSet($productSetTransfer);
    }

    /**
     * @param int $sortOrder
     *
     * @return \Generated\Shared\Transfer\ProductImageTransfer
     */
    public function createProductImageTransferWithSortOrder(int $sortOrder): ProductImageTransfer
    {
        /** @var \Generated\Shared\Transfer\ProductImageTransfer $productImageTransfer */
        $productImageTransfer = (new ProductImageBuilder())
            ->seed([ProductImageTransfer::SORT_ORDER => $sortOrder])
            ->build();

        return $productImageTransfer;
    }

    /**
     * @param int $fkProductSet
     *
     * @return void
     */
    public function deleteProductSetStorageByFkProductSet(int $fkProductSet): void
    {
        SpyProductSetStorageQuery::create()->filterByFkProductSet($fkProductSet)->delete();
    }

    /**
     * @param int $idProductSet
     *
     * @return array[]
     */
    public function getProductSetImages(int $idProductSet): array
    {
        $productSetStorage = SpyProductSetStorageQuery::create()->findOneByFkProductSet($idProductSet);

        $productSetImages = $productSetStorage->getData()['image_sets'][0]['images'];

        return $productSetImages;
    }

    /**
     * @param array $productImages
     *
     * @return void
     */
    public function assertSortingByIdProductImageSetToProductImage(array $productImages): void
    {
        $idProductImageSetToProductImagePrevious = 0;
        foreach ($productImages as $productImage) {
            $idProductImageSetToProductImage = SpyProductImageSetToProductImageQuery::create()
                ->findOneByFkProductImage($productImage['id_product_image'])
                ->getIdProductImageSetToProductImage();
            $this->assertTrue(
                $idProductImageSetToProductImage > $idProductImageSetToProductImagePrevious
            );
            $idProductImageSetToProductImagePrevious = $idProductImageSetToProductImage;
        }
    }

    /**
     * @param \Generated\Shared\Transfer\ProductSetTransfer $productSetTransfer
     *
     * @return void
     */
    public function deleteProductSet(ProductSetTransfer $productSetTransfer): void
    {
        $this->getProductSetFacade()->deleteProductSet($productSetTransfer);
    }

    /**
     * @return \Spryker\Zed\ProductSet\Business\ProductSetFacadeInterface
     */
    protected function getProductSetFacade(): ProductSetFacadeInterface
    {
        return $this->getLocator()->productSet()->facade();
    }
}
