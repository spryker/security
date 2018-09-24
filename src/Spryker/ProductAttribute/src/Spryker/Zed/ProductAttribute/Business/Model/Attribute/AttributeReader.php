<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAttribute\Business\Model\Attribute;

use Spryker\Zed\ProductAttribute\Business\Model\Attribute\Mapper\ProductAttributeTransferMapperInterface;
use Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToLocaleInterface;
use Spryker\Zed\ProductAttribute\Persistence\ProductAttributeQueryContainerInterface;
use Spryker\Zed\ProductAttribute\Persistence\ProductAttributeRepositoryInterface;
use Spryker\Zed\PropelOrm\Business\Model\Formatter\PropelArraySetFormatter;

class AttributeReader implements AttributeReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductAttribute\Persistence\ProductAttributeQueryContainerInterface
     */
    protected $productAttributeQueryContainer;

    /**
     * @var \Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToLocaleInterface
     */
    protected $localeFacade;

    /**
     * @var \Spryker\Zed\ProductAttribute\Business\Model\Attribute\Mapper\ProductAttributeTransferMapperInterface
     */
    protected $productAttributeTransferMapper;

    /**
     * @var \Spryker\Zed\ProductAttribute\Persistence\ProductAttributeRepositoryInterface
     */
    protected $productAttributeRepository;

    /**
     * @param \Spryker\Zed\ProductAttribute\Persistence\ProductAttributeQueryContainerInterface $productManagementQueryContainer
     * @param \Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToLocaleInterface $localeFacade
     * @param \Spryker\Zed\ProductAttribute\Business\Model\Attribute\Mapper\ProductAttributeTransferMapperInterface $productAttributeTransferGenerator
     * @param \Spryker\Zed\ProductAttribute\Persistence\ProductAttributeRepositoryInterface $productAttributeRepository
     */
    public function __construct(
        ProductAttributeQueryContainerInterface $productManagementQueryContainer,
        ProductAttributeToLocaleInterface $localeFacade,
        ProductAttributeTransferMapperInterface $productAttributeTransferGenerator,
        ProductAttributeRepositoryInterface $productAttributeRepository
    ) {
        $this->productAttributeQueryContainer = $productManagementQueryContainer;
        $this->localeFacade = $localeFacade;
        $this->productAttributeTransferMapper = $productAttributeTransferGenerator;
        $this->productAttributeRepository = $productAttributeRepository;
    }

    /**
     * @param int $idProductManagementAttribute
     * @param int $idLocale
     * @param string $searchText
     * @param int|null $offset
     * @param int $limit
     *
     * @return array
     */
    public function getAttributeValueSuggestions($idProductManagementAttribute, $idLocale, $searchText = '', $offset = null, $limit = 10)
    {
        $query = $this->productAttributeQueryContainer->queryProductManagementAttributeValueWithTranslation(
            $idProductManagementAttribute,
            $idLocale,
            $searchText,
            $offset,
            $limit
        );

        $results = [];
        foreach ($query->find() as $attributeEntity) {
            $data = $attributeEntity->toArray();
            $title = trim($data['translation']);
            $title = ($title === '') ? $attributeEntity->getValue() : $title;

            $results[] = [
                'id' => $attributeEntity->getIdProductManagementAttributeValue(),
                'text' => $title,
            ];
        }

        return $results;
    }

    /**
     * @param int $idProductManagementAttribute
     * @param int $idLocale
     * @param string $searchText
     * @param int|null $offset
     * @param int $limit
     *
     * @return int
     */
    public function getAttributeValueSuggestionsCount(
        $idProductManagementAttribute,
        $idLocale,
        $searchText = '',
        $offset = null,
        $limit = 10
    ) {
        $query = $this->productAttributeQueryContainer->queryProductManagementAttributeValueWithTranslation(
            $idProductManagementAttribute,
            $idLocale,
            $searchText
        );

        return $query->count();
    }

    /**
     * @param int $idProductManagementAttribute
     *
     * @return \Generated\Shared\Transfer\ProductManagementAttributeTransfer|null
     */
    public function getAttribute($idProductManagementAttribute)
    {
        $attributeEntity = $this->getAttributeEntity($idProductManagementAttribute);

        if (!$attributeEntity) {
            return null;
        }

        return $this->productAttributeTransferMapper->convertProductAttribute($attributeEntity);
    }

    /**
     * @param int $idProductManagementAttribute
     *
     * @return \Orm\Zed\ProductAttribute\Persistence\SpyProductManagementAttribute|null
     */
    protected function getAttributeEntity($idProductManagementAttribute)
    {
        return $this->productAttributeQueryContainer->queryProductManagementAttributeById($idProductManagementAttribute);
    }

    /**
     * @param string $searchText
     * @param int $limit
     *
     * @return array
     */
    public function suggestUnusedKeys($searchText = '', $limit = 10)
    {
        /** @var array $keys */
        $keys = $this->productAttributeQueryContainer
            ->queryUnusedProductAttributeKeys($searchText, $limit)
            ->setFormatter(new PropelArraySetFormatter())
            ->find();

        return $keys;
    }

    /**
     * @return \Generated\Shared\Transfer\ProductManagementAttributeTransfer[]
     */
    public function getProductAttributeCollection()
    {
        $collection = $this->productAttributeQueryContainer
            ->queryProductAttributeCollection()
            ->find();

        return $this->productAttributeTransferMapper->convertProductAttributeCollection($collection);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer[] $productConcreteTransfers
     *
     * @return \Generated\Shared\Transfer\ProductManagementAttributeTransfer[]
     */
    public function getUniqueSuperAttributesFromConcreteProducts(array $productConcreteTransfers): array
    {
        $uniqueTransaformedAttributes = $this->getUniqueTransformedAttributes($productConcreteTransfers);
        $superAttributes = $this->productAttributeRepository->findSuperAttributesFromAttributesList(array_keys($uniqueTransaformedAttributes));

        return $superAttributes;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer[] $productConcreteTransfers
     *
     * @return array
     */
    protected function getUniqueTransformedAttributes(array $productConcreteTransfers): array
    {
        $uniqueTransformedAttributes = [];

        foreach ($productConcreteTransfers as $productConcreteTransfer) {
            foreach ($productConcreteTransfer->getAttributes() as $attributeKey => $attributeValue) {
                if (!isset($uniqueTransformedAttributes[$attributeKey]) || !in_array($attributeValue, $uniqueTransformedAttributes[$attributeKey])) {
                    $uniqueTransformedAttributes[$attributeKey][] = $attributeValue;
                }
            }
        }

        return $uniqueTransformedAttributes;
    }
}
