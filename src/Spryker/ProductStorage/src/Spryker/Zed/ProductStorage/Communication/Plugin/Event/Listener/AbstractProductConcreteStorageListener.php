<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductStorage\Communication\Plugin\Event\Listener;

use Generated\Shared\Transfer\ProductConcreteStorageTransfer;
use Generated\Shared\Transfer\RawProductAttributesTransfer;
use Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\ProductStorage\Persistence\ProductStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductStorage\Communication\ProductStorageCommunicationFactory getFactory()
 */
class AbstractProductConcreteStorageListener extends AbstractPlugin
{
    const COL_FK_PRODUCT_ABSTRACT = 'fk_product_abstract';
    const COL_FK_PRODUCT = 'fk_product';
    const CONCRETE_DESCRIPTION = 'description';
    const ABSTRACT_DESCRIPTION = 'abstract_description';
    const ABSTRACT_ATTRIBUTES = 'abstract_attributes';
    const CONCRETE_ATTRIBUTES = 'attributes';

    const PRODUCT_CONCRETE_LOCALIZED_ENTITY = 'PRODUCT_CONCRETE_LOCALIZED_ENTITY';
    const PRODUCT_CONCRETE_STORAGE_ENTITY = 'PRODUCT_CONCRETE_STORAGE_ENTITY';
    const LOCALE_NAME = 'LOCALE_NAME';
    const STORE_NAME = 'STORE_NAME';
    /**
     * @var array Array keys are super attribute keys, values are "true" constants.
     */
    protected $superAttributeKeyBuffer = [];

    /**
     * @param int[] $productConcreteIds
     *
     * @return void
     */
    protected function publish(array $productConcreteIds)
    {
        $productConcreteLocalizedEntities = $this->findProductConcreteLocalizedEntities($productConcreteIds);
        $productConcreteStorageEntities = $this->findProductConcreteStorageEntities($productConcreteIds);

        if (!$productConcreteLocalizedEntities) {
            $this->deleteProductConcreteStorageEntities($productConcreteStorageEntities);

            return;
        }

        $this->storeData($productConcreteLocalizedEntities, $productConcreteStorageEntities);
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return void
     */
    protected function unpublish(array $productConcreteIds)
    {
        $productConcreteStorageEntities = $this->findProductConcreteStorageEntities($productConcreteIds);

        $this->deleteProductConcreteStorageEntities($productConcreteStorageEntities);
    }

    /**
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage[] $productConcreteStorageEntities
     *
     * @return void
     */
    protected function deleteProductConcreteStorageEntities(array $productConcreteStorageEntities)
    {
        foreach ($productConcreteStorageEntities as $productConcreteStorageEntity) {
            $productConcreteStorageEntity->delete();
        }
    }

    /**
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage $productConcreteStorageEntity
     *
     * @return void
     */
    protected function deletedProductConcreteSorageEntity(SpyProductConcreteStorage $productConcreteStorageEntity)
    {
        if (!$productConcreteStorageEntity->isNew()) {
            $productConcreteStorageEntity->delete();
        }
    }

    /**
     * @param array $productConcreteLocalizedEntities
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage[] $productConcreteStorageEntities
     *
     * @return void
     */
    protected function storeData(array $productConcreteLocalizedEntities, array $productConcreteStorageEntities)
    {
        $pairedEntities = $this->pairProductConcreteLocalizedEntitiesWithProductConcreteStorageEntities(
            $productConcreteLocalizedEntities,
            $productConcreteStorageEntities
        );

        foreach ($pairedEntities as $pair) {
            $productConcreteLocalizedEntity = $pair[static::PRODUCT_CONCRETE_LOCALIZED_ENTITY];
            $productConcreteStorageEntity = $pair[static::PRODUCT_CONCRETE_STORAGE_ENTITY];

            if ($productConcreteLocalizedEntity === null || !$this->isActive($productConcreteLocalizedEntity)) {
                $this->deletedProductConcreteSorageEntity($productConcreteStorageEntity);

                continue;
            }

            $this->storeProductConcreteStorageEntity(
                $productConcreteLocalizedEntity,
                $productConcreteStorageEntity,
                $pair[static::STORE_NAME],
                $pair[static::LOCALE_NAME]
            );
        }
    }

    /**
     * @param array $productConcreteLocalizedEntities
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage[] $productConcreteStorageEntities
     *
     * @return array
     */
    protected function pairProductConcreteLocalizedEntitiesWithProductConcreteStorageEntities(
        array $productConcreteLocalizedEntities,
        array $productConcreteStorageEntities
    ) {
        $mappedProductConcreteStorageEntities = $this->mapProductConcreteStorageEntities($productConcreteStorageEntities);

        $pairs = [];
        foreach ($productConcreteLocalizedEntities as $productConcreteLocalizedEntity) {
            list($pairs, $mappedProductConcreteStorageEntities) = $this->pairProductConcreteLocalizedEntitiesWithProductConcreteStorageEntitiesByStoresAndLocales(
                $productConcreteLocalizedEntity[static::COL_FK_PRODUCT],
                $productConcreteLocalizedEntity['Locale']['locale_name'],
                $productConcreteLocalizedEntity,
                $productConcreteLocalizedEntity['SpyProduct']['SpyProductAbstract']['SpyProductAbstractStores'],
                $mappedProductConcreteStorageEntities,
                $pairs
            );
        }

        $pairs = $this->pairRemainingProductConcreteStorageEntities($mappedProductConcreteStorageEntities, $pairs);

        return $pairs;
    }

    /**
     * @param int $idProduct
     * @param string $localeName
     * @param array $productConcreteLocalizedEntity
     * @param array $productAbstractStoreEntities
     * @param array $mappedProductConcreteStorageEntities
     * @param array $pairs
     *
     * @return array
     */
    protected function pairProductConcreteLocalizedEntitiesWithProductConcreteStorageEntitiesByStoresAndLocales(
        $idProduct,
        $localeName,
        $productConcreteLocalizedEntity,
        $productAbstractStoreEntities,
        array $mappedProductConcreteStorageEntities,
        array $pairs
    ) {
        foreach ($productAbstractStoreEntities as $productAbstractStoreEntity) {
            $storeName = $productAbstractStoreEntity['SpyStore']['name'];

            $productConcreteStorageEntity = isset($mappedProductConcreteStorageEntities[$idProduct][$storeName][$localeName]) ?
                $mappedProductConcreteStorageEntities[$idProduct][$storeName][$localeName] :
                new SpyProductConcreteStorage();

            $pairs[] = [
                static::PRODUCT_CONCRETE_LOCALIZED_ENTITY => $productConcreteLocalizedEntity,
                static::PRODUCT_CONCRETE_STORAGE_ENTITY => $productConcreteStorageEntity,
                static::LOCALE_NAME => $localeName,
                static::STORE_NAME => $storeName,
            ];

            unset($mappedProductConcreteStorageEntities[$idProduct][$storeName][$localeName]);
        }

        return [$pairs, $mappedProductConcreteStorageEntities];
    }

    /**
     * @param array $mappedProductConcreteStorageEntities
     * @param array $pairs
     *
     * @return array
     */
    protected function pairRemainingProductConcreteStorageEntities(array $mappedProductConcreteStorageEntities, array $pairs)
    {
        array_walk_recursive($mappedProductConcreteStorageEntities, function (SpyProductConcreteStorage $productConcreteStorageEntity) use (&$pairs) {
            $pairs[] = [
                static::PRODUCT_CONCRETE_LOCALIZED_ENTITY => null,
                static::PRODUCT_CONCRETE_STORAGE_ENTITY => $productConcreteStorageEntity,
                static::LOCALE_NAME => $productConcreteStorageEntity->getLocale(),
                static::STORE_NAME => $productConcreteStorageEntity->getStore(),
            ];
        });

        return $pairs;
    }

    /**
     * @param array $productConcreteLocalizedEntity
     *
     * @return bool
     */
    protected function isActive(array $productConcreteLocalizedEntity)
    {
        return (bool)$productConcreteLocalizedEntity['SpyProduct']['is_active'];
    }

    /**
     * @param array $productConcreteLocalizedEntity
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage $productConcreteStorageEntity
     * @param string $storeName
     * @param string $localeName
     *
     * @return void
     */
    protected function storeProductConcreteStorageEntity(
        array $productConcreteLocalizedEntity,
        SpyProductConcreteStorage $productConcreteStorageEntity,
        $storeName,
        $localeName
    ) {
        $productConcreteStorageTransfer = $this->mapToProductConcreteStorageTransfer($productConcreteLocalizedEntity);

        $productConcreteStorageEntity
            ->setFkProduct($productConcreteLocalizedEntity[static::COL_FK_PRODUCT])
            ->setData($productConcreteStorageTransfer->toArray())
            ->setStore($storeName)
            ->setLocale($localeName)
            ->save();
    }

    /**
     * @param array $productConcreteLocalizedEntity
     *
     * @return \Generated\Shared\Transfer\ProductConcreteStorageTransfer
     */
    protected function mapToProductConcreteStorageTransfer(array $productConcreteLocalizedEntity)
    {
        $attributes = $this->getConcreteAttributes($productConcreteLocalizedEntity);

        $spyProductConcreteEntityArray = $productConcreteLocalizedEntity['SpyProduct'];
        unset($productConcreteLocalizedEntity['attributes']);
        unset($spyProductConcreteEntityArray['attributes']);

        $productStorageTransfer = (new ProductConcreteStorageTransfer())
            ->fromArray($productConcreteLocalizedEntity, true)
            ->fromArray($spyProductConcreteEntityArray, true)
            ->setIdProductConcrete($productConcreteLocalizedEntity[static::COL_FK_PRODUCT])
            ->setIdProductAbstract($spyProductConcreteEntityArray[static::COL_FK_PRODUCT_ABSTRACT])
            ->setDescription($this->getDescription($productConcreteLocalizedEntity))
            ->setAttributes($attributes)
            ->setSuperAttributesDefinition($this->getSuperAttributeKeys($attributes));

        return $productStorageTransfer;
    }

    /**
     * @param array $productConcreteLocalizedEntity
     *
     * @return array
     */
    protected function getConcreteAttributes(array $productConcreteLocalizedEntity)
    {
        $abstractDecodedAttributes = $this->getFactory()
            ->getProductFacade()
            ->decodeProductAttributes($productConcreteLocalizedEntity['SpyProduct']['SpyProductAbstract']['attributes']);
        $concreteDecodedAttributes = $this->getFactory()
            ->getProductFacade()
            ->decodeProductAttributes($productConcreteLocalizedEntity['SpyProduct']['attributes']);

        $abstractLocalizedDecodedAttributes = $this->getFactory()
            ->getProductFacade()
            ->decodeProductAttributes($productConcreteLocalizedEntity[static::ABSTRACT_ATTRIBUTES]);
        $concreteLocalizedDecodedAttributes = $this->getFactory()
            ->getProductFacade()
            ->decodeProductAttributes($productConcreteLocalizedEntity[static::CONCRETE_ATTRIBUTES]);

        $rawProductAttributesTransfer = (new RawProductAttributesTransfer())
            ->setAbstractAttributes($abstractDecodedAttributes)
            ->setAbstractLocalizedAttributes($abstractLocalizedDecodedAttributes)
            ->setConcreteAttributes($concreteDecodedAttributes)
            ->setConcreteLocalizedAttributes($concreteLocalizedDecodedAttributes);

        return $this->getFactory()->getProductFacade()->combineRawProductAttributes($rawProductAttributesTransfer);
    }

    /**
     * @param array $productConcreteLocalizedEntity
     *
     * @return string
     */
    protected function getDescription(array $productConcreteLocalizedEntity)
    {
        $description = trim($productConcreteLocalizedEntity[static::CONCRETE_DESCRIPTION]);
        if (!$description) {
            $description = trim($productConcreteLocalizedEntity[static::ABSTRACT_DESCRIPTION]);
        }

        return $description;
    }

    /**
     * @param array $attributes
     *
     * @return array
     */
    protected function getSuperAttributeKeys(array $attributes)
    {
        if (empty($this->superAttributeKeyBuffer)) {
            $this->loadSuperAttributes();
        }

        return $this->filterSuperAttributeKeys($attributes);
    }

    /**
     * @return void
     */
    protected function loadSuperAttributes()
    {
        $superAttributes = $this->getQueryContainer()
            ->queryProductAttributeKey()
            ->find();

        foreach ($superAttributes as $attribute) {
            $this->superAttributeKeyBuffer[$attribute->getKey()] = true;
        }
    }

    /**
     * @param array $attributes Array keys are attribute keys.
     *
     * @return string[]
     */
    protected function filterSuperAttributeKeys(array $attributes)
    {
        $superAttributes = array_intersect_key($attributes, $this->superAttributeKeyBuffer);

        return array_keys($superAttributes);
    }

    /**
     * @param int[] $productConcreteIds
     *
     * @return array
     */
    protected function findProductConcreteLocalizedEntities(array $productConcreteIds)
    {
        return $this->getQueryContainer()->queryProductConcreteByIds($productConcreteIds)->find()->getData();
    }

    /**
     * @param array $productConcreteIds
     *
     * @return array
     */
    protected function findProductConcreteStorageEntities(array $productConcreteIds)
    {
        return $this->getQueryContainer()->queryProductConcreteStorageByIds($productConcreteIds)->find()->getArrayCopy();
    }

    /**
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductConcreteStorage[] $productConcreteStorageEntities
     *
     * @return array
     */
    protected function mapProductConcreteStorageEntities(array $productConcreteStorageEntities)
    {
        $map = [];
        foreach ($productConcreteStorageEntities as $entity) {
            $map[$entity->getFkProductAbstract()][$entity->getStore()][$entity->getLocale()] = $entity;
        }

        return $map;
    }
}
