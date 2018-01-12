<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductImageStorage\Expander;

use Generated\Shared\Transfer\ProductViewTransfer;
use Spryker\Client\ProductImageStorage\Storage\ProductAbstractImageStorageReaderInterface;
use Spryker\Client\ProductImageStorage\Storage\ProductConcreteImageStorageReaderInterface;
use Spryker\Shared\ProductImageStorage\ProductImageStorageConfig;

class ProductViewImageExpander implements ProductViewImageExpanderInterface
{
    /**
     * @var \Spryker\Client\ProductImageStorage\Storage\ProductAbstractImageStorageReaderInterface
     */
    protected $productAbstractImageSetReader;

    /**
     * @var \Spryker\Client\ProductImageStorage\Storage\ProductConcreteImageStorageReaderInterface
     */
    protected $productConcreteImageSetReader;

    /**
     * @param \Spryker\Client\ProductImageStorage\Storage\ProductAbstractImageStorageReaderInterface $productAbstractImageSetReader
     * @param \Spryker\Client\ProductImageStorage\Storage\ProductConcreteImageStorageReaderInterface $productConcreteImageSetReader
     */
    public function __construct(ProductAbstractImageStorageReaderInterface $productAbstractImageSetReader, ProductConcreteImageStorageReaderInterface $productConcreteImageSetReader)
    {
        $this->productAbstractImageSetReader = $productAbstractImageSetReader;
        $this->productConcreteImageSetReader = $productConcreteImageSetReader;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductViewTransfer $productViewTransfer
     * @param string $locale
     * @param string $imageSetName
     *
     * @return \Generated\Shared\Transfer\ProductViewTransfer
     */
    public function expandProductViewImageData(ProductViewTransfer $productViewTransfer, $locale, $imageSetName = ProductImageStorageConfig::DEFAULT_IMAGE_SET_NAME)
    {
        $images = $this->getImages($productViewTransfer, $locale, $imageSetName);

        if ($images) {
            $productViewTransfer->setImages($images);
        }

        return $productViewTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductViewTransfer $productViewTransfer
     * @param string $locale
     * @param string $imageSetName
     *
     * @return \Generated\Shared\Transfer\ProductImageStorageTransfer[]|null
     */
    protected function getImages(ProductViewTransfer $productViewTransfer, $locale, $imageSetName)
    {
        if ($productViewTransfer->getIdProductConcrete()) {
            $productConcreteImageSetCollection = $this->productConcreteImageSetReader
                ->findProductImageConcreteStorageTransfer($productViewTransfer->getIdProductConcrete(), $locale);

            if (!$productConcreteImageSetCollection) {
                return null;
            }

            return $this->getImageSetImages($productConcreteImageSetCollection->getImageSets(), $imageSetName);
        }

        $productAbstractImageSetCollection = $this->productAbstractImageSetReader
            ->findProductImageAbstractStorageTransfer($productViewTransfer->getIdProductAbstract(), $locale);

        if (!$productAbstractImageSetCollection) {
            return null;
        }

        return $this->getImageSetImages($productAbstractImageSetCollection->getImageSets(), $imageSetName);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductImageSetStorageTransfer[] $imageSetStorageCollection
     * @param string $imageSetName
     *
     * @return \Generated\Shared\Transfer\ProductImageStorageTransfer[]|null
     */
    protected function getImageSetImages($imageSetStorageCollection, $imageSetName)
    {
        foreach ($imageSetStorageCollection as $productImageSetStorageTransfer) {
            if ($productImageSetStorageTransfer->getName() !== $imageSetName) {
                continue;
            }

            return $productImageSetStorageTransfer->getImages();
        }

        if ($imageSetName !== ProductImageStorageConfig::DEFAULT_IMAGE_SET_NAME) {
            return $this->getImageSetImages($imageSetStorageCollection, ProductImageStorageConfig::DEFAULT_IMAGE_SET_NAME);
        }

        return null;
    }
}
