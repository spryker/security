<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPageSearch\Business\Mapper;

use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\ProductPageSearchTransfer;
use Spryker\Shared\Kernel\Store;
use Spryker\Shared\ProductPageSearch\ProductPageSearchConstants;
use Spryker\Zed\ProductPageSearch\Business\Attribute\ProductPageAttributeInterface;
use Spryker\Zed\ProductPageSearch\Dependency\Facade\ProductPageSearchToSearchInterface;
use Spryker\Zed\ProductPageSearch\Dependency\Service\ProductPageSearchToUtilEncodingInterface;

class ProductPageSearchMapper implements ProductPageSearchMapperInterface
{
    /**
     * @var \Spryker\Zed\ProductPageSearch\Business\Attribute\ProductPageAttributeInterface
     */
    protected $productPageAttributes;

    /**
     * @var \Spryker\Zed\ProductPageSearch\Dependency\Facade\ProductPageSearchToSearchInterface
     */
    protected $searchFacade;

    /**
     * @var \Spryker\Zed\ProductPageSearch\Dependency\Service\ProductPageSearchToUtilEncodingInterface
     */
    protected $utilEncoding;

    /**
     * @var \Spryker\Shared\Kernel\Store
     */
    protected $store;

    /**
     * @param \Spryker\Zed\ProductPageSearch\Business\Attribute\ProductPageAttributeInterface $productPageAttributes
     * @param \Spryker\Zed\ProductPageSearch\Dependency\Facade\ProductPageSearchToSearchInterface $searchFacade
     * @param \Spryker\Zed\ProductPageSearch\Dependency\Service\ProductPageSearchToUtilEncodingInterface $utilEncoding
     * @param \Spryker\Shared\Kernel\Store $store
     */
    public function __construct(ProductPageAttributeInterface $productPageAttributes, ProductPageSearchToSearchInterface $searchFacade, ProductPageSearchToUtilEncodingInterface $utilEncoding, Store $store)
    {
        $this->productPageAttributes = $productPageAttributes;
        $this->searchFacade = $searchFacade;
        $this->utilEncoding = $utilEncoding;
        $this->store = $store;
    }

    /**
     * @param array $productAbstractLocalizedData
     *
     * @return \Generated\Shared\Transfer\ProductPageSearchTransfer
     */
    public function mapToProductPageSearchTransfer(array $productAbstractLocalizedData)
    {
        $concreteData = $this->getConcreteProductData($productAbstractLocalizedData['SpyProductAbstract']['SpyProducts'], $productAbstractLocalizedData['Locale']['id_locale']);
        $attributes = $this->productPageAttributes->getCombinedProductAttributes(
            $productAbstractLocalizedData['SpyProductAbstract']['attributes'],
            $productAbstractLocalizedData['attributes'],
            $concreteData['concreteAttributes'],
            $concreteData['concreteLocalizedAttributes']
        );

        $productPageSearchTransfer = new ProductPageSearchTransfer();
        $productPageSearchTransfer->setIdProductAbstract($productAbstractLocalizedData['fk_product_abstract']);
        $productPageSearchTransfer->setIdImageSet($productAbstractLocalizedData['id_image_set']);
        $productPageSearchTransfer->setCategoryNodeIds($this->getCategoryNodeIds($productAbstractLocalizedData['SpyProductAbstract']['SpyProductCategories']));
        $productPageSearchTransfer->setIsActive(true);
        $productPageSearchTransfer->setSku($productAbstractLocalizedData['SpyProductAbstract']['sku']);
        $productPageSearchTransfer->setName($productAbstractLocalizedData['name']);
        $productPageSearchTransfer->setUrl($productAbstractLocalizedData['url']);
        $productPageSearchTransfer->setAbstractDescription($productAbstractLocalizedData['description']);
        $productPageSearchTransfer->setConcreteDescription($concreteData['concreteDescriptions']);
        $productPageSearchTransfer->setConcreteSkus($concreteData['concreteSkus']);
        $productPageSearchTransfer->setConcreteNames($concreteData['concreteNames']);
        $productPageSearchTransfer->setType(ProductPageSearchConstants::PRODUCT_ABSTRACT_RESOURCE_NAME);
        $productPageSearchTransfer->setLocale($productAbstractLocalizedData['Locale']['locale_name']);
        $productPageSearchTransfer->setAttributes($attributes);
        $productPageSearchTransfer->setStore($this->getStoreName());

        return $productPageSearchTransfer;
    }

    /**
     * @param string $data
     *
     * @return \Generated\Shared\Transfer\ProductPageSearchTransfer
     */
    public function mapToProductPageSearchTransferFromJson($data)
    {
        $productAbstractPageSearchTransfer = new ProductPageSearchTransfer();
        $productAbstractPageSearchTransfer->fromArray($this->utilEncoding->decodeJson($data, true));

        return $productAbstractPageSearchTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductPageSearchTransfer $productPageSearchTransfer
     *
     * @return array
     */
    public function mapToSearchData(ProductPageSearchTransfer $productPageSearchTransfer)
    {
        return $this->searchFacade
            ->transformPageMapToDocumentByMapperName(
                $productPageSearchTransfer->toArray(),
                (new LocaleTransfer())->setLocaleName($productPageSearchTransfer->getLocale()),
                ProductPageSearchConstants::PRODUCT_ABSTRACT_RESOURCE_NAME
            );
    }

    /**
     * @param array $productCategories
     *
     * @return array
     */
    protected function getCategoryNodeIds(array $productCategories)
    {
        $categoryNodeIds = [];
        foreach ($productCategories as $productCategory) {
            foreach ($productCategory['SpyCategory']['Nodes'] as $node) {
                $categoryNodeIds[] = $node['id_category_node'];
            }
        }

        return $categoryNodeIds;
    }

    /**
     * @param array $concreteProducts
     * @param int $idLocale
     *
     * @return array
     */
    protected function getConcreteProductData(array $concreteProducts, $idLocale)
    {
        $concreteNames = [];
        $concreteSkus = [];
        $concreteAttributes = [];
        $concreteLocalizedAttributes = [];
        $concreteDescriptions = [];

        foreach ($concreteProducts as $concreteProduct) {
            $concreteSkus[] = $concreteProduct['sku'];
            $concreteAttributes[] = $concreteProduct['attributes'];
            $this->setConcreteLocalizedProductData(
                $concreteProduct['SpyProductLocalizedAttributess'],
                $idLocale,
                $concreteNames,
                $concreteDescriptions,
                $concreteLocalizedAttributes
            );
        }

        return [
            'concreteNames' => implode(',', $concreteNames),
            'concreteSkus' => implode(',', $concreteSkus),
            'concreteAttributes' => implode(',', $concreteAttributes),
            'concreteLocalizedAttributes' => implode(',', $concreteLocalizedAttributes),
            'concreteDescriptions' => implode(',', $concreteDescriptions),
        ];
    }

    /**
     * @param array $concreteProductLocalizedAttributes
     * @param int $idLocale
     * @param array $concreteNames
     * @param array $concreteDescriptions
     * @param array $concreteLocalizedAttributes
     *
     * @return void
     */
    protected function setConcreteLocalizedProductData(array $concreteProductLocalizedAttributes, $idLocale, array &$concreteNames, array &$concreteDescriptions, array &$concreteLocalizedAttributes)
    {
        $concreteNames = [];
        foreach ($concreteProductLocalizedAttributes as $concreteProductLocalizedAttribute) {
            if ($concreteProductLocalizedAttribute['fk_locale'] === $idLocale) {
                $concreteNames[] = $concreteProductLocalizedAttribute['name'];
                $concreteDescriptions[] = $concreteProductLocalizedAttribute['description'];
                $concreteLocalizedAttributes[] = $concreteProductLocalizedAttribute['attributes'];
            }
        }
    }

    /**
     * @return string
     */
    protected function getStoreName()
    {
        return $this->store->getStoreName();
    }
}
