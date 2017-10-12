<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductManagement\Communication\Controller;

use Generated\Shared\Transfer\ProductImageSetTransfer;
use Spryker\Shared\ProductManagement\ProductManagementConstants;
use Spryker\Zed\ProductManagement\Communication\Form\Product\ImageCollectionForm;
use Spryker\Zed\ProductManagement\Communication\Form\Product\ImageSetForm;
use Spryker\Zed\ProductManagement\ProductManagementConfig;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\ProductManagement\Business\ProductManagementFacade getFacade()
 * @method \Spryker\Zed\ProductManagement\Communication\ProductManagementCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductManagement\Persistence\ProductManagementQueryContainer getQueryContainer()
 */
class ViewController extends AddController
{
    const PARAM_ID_PRODUCT_ABSTRACT = 'id-product-abstract';
    const PARAM_ID_PRODUCT = 'id-product';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $idProductAbstract = $this->castId($request->get(
            self::PARAM_ID_PRODUCT_ABSTRACT
        ));

        $productAbstractTransfer = $this->getFactory()
            ->getProductFacade()
            ->findProductAbstractById($idProductAbstract);

        if (!$productAbstractTransfer) {
            $this->addErrorMessage(sprintf('The product [%s] you are trying to edit, does not exist.', $idProductAbstract));

            return new RedirectResponse('/product-management');
        }

        $concreteProductCollection = $this->getFactory()
            ->getProductFacade()
            ->getConcreteProductsByAbstractProductId($idProductAbstract);

        $localeProvider = $this->getFactory()->createLocaleProvider();

        $variantTable = $this
            ->getFactory()
            ->createVariantTable($idProductAbstract, ProductManagementConfig::PRODUCT_TYPE_REGULAR);

        $productGroupTable = $this->getFactory()
            ->createProductGroupTable($idProductAbstract);

        $attributes[ProductManagementConstants::PRODUCT_MANAGEMENT_DEFAULT_LOCALE] = $productAbstractTransfer->getAttributes();
        foreach ($productAbstractTransfer->getLocalizedAttributes() as $localizedAttributesTransfer) {
            $attributes[$localizedAttributesTransfer->getLocale()->getLocaleName()] = $localizedAttributesTransfer->getAttributes();
        }

        $imageSetCollection = $this->getFactory()->getProductImageFacade()
            ->getProductImagesSetCollectionByProductAbstractId($productAbstractTransfer->getIdProductAbstract());

        $imageSets = $this->getProductImageSetCollection($imageSetCollection);

        return $this->viewResponse([
            'currentLocale' => $this->getFactory()->getLocaleFacade()->getCurrentLocale()->getLocaleName(),
            'currentProduct' => $productAbstractTransfer->toArray(),
            'concreteProductCollection' => $concreteProductCollection,
            'localeCollection' => $localeProvider->getLocaleCollection(),
            'attributeLocaleCollection' => $localeProvider->getLocaleCollection(true),
            'variantTable' => $variantTable->render(),
            'productGroupTable' => $productGroupTable->render(),
            'idProduct' => null,
            'idProductAbstract' => $idProductAbstract,
            'productAttributes' => $attributes,
            'imageSetCollection' => $imageSets,
            'imageUrlPrefix' => $this->getFactory()->getConfig()->getImageUrlPrefix(),
            'taxSet' => $this->getFactory()->getTaxFacade()->getTaxSet($productAbstractTransfer->getIdTaxSet()),
            'renderedPlugins' => $this->getRenderedProductAbstractViewPlugins($idProductAbstract),
        ]);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function variantAction(Request $request)
    {
        $idProductAbstract = $this->castId($request->get(
            self::PARAM_ID_PRODUCT_ABSTRACT
        ));

        $idProduct = $this->castId($request->get(
            self::PARAM_ID_PRODUCT
        ));

        $productTransfer = $this->getFactory()
            ->getProductFacade()
            ->findProductConcreteById($idProduct);

        $stockTypes = $this->getFactory()->getStockQueryContainer()->queryAllStockTypes()->find()->getData();
        $this->getFactory()->createProductStockHelper()->addMissingStockTypes($productTransfer, $stockTypes);

        if (!$productTransfer) {
            $this->addErrorMessage(sprintf('The product [%s] you are trying to edit, does not exist.', $idProduct));

            return new RedirectResponse('/product-management/edit?id-product-abstract=' . $idProductAbstract);
        }

        $localeProvider = $this->getFactory()->createLocaleProvider();

        $attributes[ProductManagementConstants::PRODUCT_MANAGEMENT_DEFAULT_LOCALE] = $productTransfer->getAttributes();
        foreach ($productTransfer->getLocalizedAttributes() as $localizedAttributesTransfer) {
            $attributes[$localizedAttributesTransfer->getLocale()->getLocaleName()] = $localizedAttributesTransfer->getAttributes();
        }

        $imageSetCollection = $this->getFactory()->getProductImageFacade()
            ->getProductImagesSetCollectionByProductId($productTransfer->getIdProductConcrete());

        $imageSets = $this->getProductImageSetCollection($imageSetCollection);

        return $this->viewResponse([
            'currentLocale' => $this->getFactory()->getLocaleFacade()->getCurrentLocale()->getLocaleName(),
            'currentProduct' => $productTransfer->toArray(),
            'localeCollection' => $localeProvider->getLocaleCollection(),
            'attributeLocaleCollection' => $localeProvider->getLocaleCollection(true),
            'idProduct' => $productTransfer->getIdProductConcrete(),
            'idProductAbstract' => $idProductAbstract,
            'productAttributes' => $attributes,
            'imageSetCollection' => $imageSets,
        ]);
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function variantTableAction(Request $request)
    {
        $idProductAbstract = $this->castId($request->get(
            self::PARAM_ID_PRODUCT_ABSTRACT
        ));

        $variantTable = $this
            ->getFactory()
            ->createVariantTable($idProductAbstract, ProductManagementConfig::PRODUCT_TYPE_REGULAR);

        return $this->jsonResponse(
            $variantTable->fetchData()
        );
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\JsonResponse
     */
    public function productGroupTableAction(Request $request)
    {
        $idProductAbstract = $this->castId($request->get(
            self::PARAM_ID_PRODUCT_ABSTRACT
        ));

        $productGroupTable = $this
            ->getFactory()
            ->createProductGroupTable($idProductAbstract);

        return $this->jsonResponse(
            $productGroupTable->fetchData()
        );
    }

    /**
     * @param \Generated\Shared\Transfer\ProductImageSetTransfer[] $imageSetTransferCollection
     *
     * @return array
     */
    protected function getProductImageSetCollection($imageSetTransferCollection)
    {
        $localeCollection = $this->getFactory()->getLocaleFacade()->getLocaleCollection();

        $result = [];
        $defaults = [];
        foreach ($localeCollection as $localeTransfer) {
            $data = [];
            foreach ($imageSetTransferCollection as $imageSetTransfer) {
                if ($imageSetTransfer->getLocale() === null) {
                    $defaults[$imageSetTransfer->getIdProductImageSet()] = $this->convertProductImageSet($imageSetTransfer);
                    continue;
                }

                $fkLocale = (int)$imageSetTransfer->getLocale()->getIdLocale();
                if ($fkLocale !== (int)$localeTransfer->getIdLocale()) {
                    continue;
                }

                $data[$imageSetTransfer->getIdProductImageSet()] = $this->convertProductImageSet($imageSetTransfer);
            }

            $result[$localeTransfer->getLocaleName()] = array_values($data);
        }

        $result[ProductManagementConstants::PRODUCT_MANAGEMENT_DEFAULT_LOCALE] = array_values($defaults);

        return $result;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductImageSetTransfer $imageSetTransfer
     *
     * @return array
     */
    protected function convertProductImageSet(ProductImageSetTransfer $imageSetTransfer)
    {
        $item = $imageSetTransfer->toArray();
        $itemImages = [];

        $imageUrlPrefix = $this->getFactory()->getConfig()->getImageUrlPrefix();

        foreach ($imageSetTransfer->getProductImages() as $imageTransfer) {
            $image = $imageTransfer->toArray();
            $image[ImageCollectionForm::FIELD_IMAGE_PREVIEW] = $this->getImageUrl($image[ImageCollectionForm::FIELD_IMAGE_SMALL], $imageUrlPrefix);
            $image[ImageCollectionForm::FIELD_IMAGE_PREVIEW_LARGE_URL] = $this->getImageUrl($image[ImageCollectionForm::FIELD_IMAGE_SMALL], $image[ImageCollectionForm::FIELD_IMAGE_LARGE]);
            $image[ImageCollectionForm::FIELD_FK_IMAGE_SET_ID] = $imageSetTransfer->getIdProductImageSet();
            $itemImages[] = $image;
        }

        $item[ImageSetForm::PRODUCT_IMAGES] = $itemImages;

        return $item;
    }

    /**
     * @param string $baseUrl
     * @param string $imageUrlPrefix
     *
     * @return string
     */
    protected function getImageUrl($baseUrl, $imageUrlPrefix)
    {
        $url = $baseUrl;

        if (strpos($url, '/') === 0) {
            $url = $imageUrlPrefix . $url;
        }

        return $url;
    }

    /**
     * @param int $idProductAbstract
     *
     * @return array
     */
    protected function getRenderedProductAbstractViewPlugins($idProductAbstract)
    {
        $productAbstractViewPlugins = $this->getFactory()
            ->getProductAbstractViewPlugins();

        $productAbstractRenderedPlugins = [];
        foreach ($productAbstractViewPlugins as $productAbstractViewPlugin) {
            $productAbstractRenderedPlugins[$productAbstractViewPlugin->getName()] =
                $productAbstractViewPlugin->getRenderedList($idProductAbstract);
        }

        return $productAbstractRenderedPlugins;
    }
}
