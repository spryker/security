<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductStorage\Communication\Plugin\Event\Listener;

use Generated\Shared\Transfer\ProductAbstractStorageTransfer;
use Generated\Shared\Transfer\RawProductAttributesTransfer;
use Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\ProductStorage\Persistence\ProductStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductStorage\Communication\ProductStorageCommunicationFactory getFactory()
 */

class AbstractProductAbstractStorageListener extends AbstractPlugin
{
    const COL_ID_PRODUCT_ABSTRACT = 'id_product_abstract';
    const COL_FK_PRODUCT_ABSTRACT = 'fk_product_abstract';

    const PRODUCT_ABSTRACT_LOCALIZED_ENTITY = 'PRODUCT_ABSTRACT_LOCALIZED_ENTITY';
    const PRODUCT_ABSTRACT_STORAGE_ENTITY = 'PRODUCT_ABSTRACT_STORAGE_ENTITY';
    const LOCALE_NAME = 'LOCALE_NAME';
    const STORE_NAME = 'STORE_NAME';

    /**
     * @var array Array keys are super attribute keys, values are constant trues.
     */
    protected $superAttributeKeyBuffer = [];

    /**
     * @param array $productAbstractIds
     *
     * @return void
     */
    protected function publish(array $productAbstractIds)
    {
        $productAbstractLocalizedEntities = $this->findProductAbstractLocalizedEntities($productAbstractIds);
        $productAbstractStorageEntities = $this->findProductAbstractStorageEntities($productAbstractIds);

        if (!$productAbstractLocalizedEntities) {
            $this->deleteProductAbstractStorageEntities($productAbstractStorageEntities);

            return;
        }

        $this->storeData($productAbstractLocalizedEntities, $productAbstractStorageEntities);
    }

    /**
     * @param array $productAbstractIds
     *
     * @return void
     */
    protected function unpublish(array $productAbstractIds)
    {
        $spyProductStorageEntities = $this->findProductAbstractStorageEntities($productAbstractIds);

        $this->deleteProductAbstractStorageEntities($spyProductStorageEntities);
    }

    /**
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage[] $productAbstractStorageEntities
     *
     * @return void
     */
    protected function deleteProductAbstractStorageEntities(array $productAbstractStorageEntities)
    {
        foreach ($productAbstractStorageEntities as $productAbstractStorageEntity) {
            $productAbstractStorageEntity->delete();
        }
    }

    /**
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage $productAbstractStorage
     *
     * @return void
     */
    protected function deleteProductAbstractStorageEntity(SpyProductAbstractStorage $productAbstractStorage)
    {
        if (!$productAbstractStorage->isNew()) {
            $productAbstractStorage->delete();
        }
    }

    /**
     * @param array $productAbstractLocalizedEntities
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage[] $productAbstractStorageEntities
     *
     * @return void
     */
    protected function storeData(array $productAbstractLocalizedEntities, array $productAbstractStorageEntities)
    {
        $pairedEntities = $this->pairProductAbstractLocalizedEntitiesWithProductAbstractStorageEntities(
            $productAbstractLocalizedEntities,
            $productAbstractStorageEntities
        );

        foreach ($pairedEntities as $pair) {
            $productAbstractLocalizedEntity = $pair[static::PRODUCT_ABSTRACT_LOCALIZED_ENTITY];
            $productAbstractStorageEntity = $pair[static::PRODUCT_ABSTRACT_STORAGE_ENTITY];

            if ($productAbstractLocalizedEntity === null || !$this->isActive($productAbstractLocalizedEntity)) {
                $this->deleteProductAbstractStorageEntity($productAbstractStorageEntity);

                continue;
            }

            $this->storeProductAbstractStorageEntity(
                $productAbstractLocalizedEntity,
                $productAbstractStorageEntity,
                $pair[static::STORE_NAME],
                $pair[static::LOCALE_NAME]
            );
        }
    }

    /**
     * @param array $productAbstractLocalizedEntities
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage[] $productAbstractStorageEntities
     *
     * @return array
     */
    protected function pairProductAbstractLocalizedEntitiesWithProductAbstractStorageEntities(
        array $productAbstractLocalizedEntities,
        array $productAbstractStorageEntities
    ) {
        $mappedProductAbstractStorageEntities = $this->mapProductAbstractStorageEntities($productAbstractStorageEntities);

        $pairs = [];
        foreach ($productAbstractLocalizedEntities as $productAbstractLocalizedEntity) {
            list($pairs, $mappedProductAbstractStorageEntities) = $this->pairProductAbstractLocalizedEntitiesWithProductAbstractStorageEntitiesByStoresAndLocales(
                $productAbstractLocalizedEntity['SpyProductAbstract'][static::COL_ID_PRODUCT_ABSTRACT],
                $productAbstractLocalizedEntity['Locale']['locale_name'],
                $productAbstractLocalizedEntity,
                $productAbstractLocalizedEntity['SpyProductAbstract']['SpyProductAbstractStores'],
                $mappedProductAbstractStorageEntities,
                $pairs
            );
        }

        $pairs = $this->pairRemainingProductAbstractStorageEntities($mappedProductAbstractStorageEntities, $pairs);

        return $pairs;
    }

    /**
     * @param int $idProduct
     * @param string $localeName
     * @param array $productAbstractLocalizedEntity
     * @param array $productAbstractStoreEntities
     * @param array $mappedProductAbstractStorageEntities
     * @param array $pairs
     *
     * @return array
     */
    protected function pairProductAbstractLocalizedEntitiesWithProductAbstractStorageEntitiesByStoresAndLocales(
        $idProduct,
        $localeName,
        array $productAbstractLocalizedEntity,
        array $productAbstractStoreEntities,
        array $mappedProductAbstractStorageEntities,
        array $pairs
    ) {
        foreach ($productAbstractStoreEntities as $productAbstractStoreEntity) {
            $storeName = $productAbstractStoreEntity['SpyStore']['name'];

            $productAbstractStorageEntity = isset($mappedProductAbstractStorageEntities[$idProduct][$storeName][$localeName]) ?
                $mappedProductAbstractStorageEntities[$idProduct][$storeName][$localeName] :
                new SpyProductAbstractStorage();

            $pairs[] = [
                static::PRODUCT_ABSTRACT_LOCALIZED_ENTITY => $productAbstractLocalizedEntity,
                static::PRODUCT_ABSTRACT_STORAGE_ENTITY => $productAbstractStorageEntity,
                static::LOCALE_NAME => $localeName,
                static::STORE_NAME => $storeName,
            ];

            unset($mappedProductAbstractStorageEntities[$idProduct][$storeName][$localeName]);
        }

        return [$pairs, $mappedProductAbstractStorageEntities];
    }

    /**
     * @param array $mappedProductAbstractStorageEntities
     * @param array $pairs
     *
     * @return array
     */
    protected function pairRemainingProductAbstractStorageEntities(array $mappedProductAbstractStorageEntities, array $pairs)
    {
        array_walk_recursive($mappedProductAbstractStorageEntities, function (SpyProductAbstractStorage $productAbstractStorageEntity) use (&$pairs) {
            $pairs[] = [
                static::PRODUCT_ABSTRACT_LOCALIZED_ENTITY => null,
                static::PRODUCT_ABSTRACT_STORAGE_ENTITY => $productAbstractStorageEntity,
                static::LOCALE_NAME => $productAbstractStorageEntity->getLocale(),
                static::STORE_NAME => $productAbstractStorageEntity->getStore(),
            ];
        });

        return $pairs;
    }

    /**
     * @param array $productAbstractLocalizedEntity
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage $spyProductStorageEntity
     * @param string $storeName
     * @param string $localeName
     *
     * @return void
     */
    protected function storeProductAbstractStorageEntity(
        array $productAbstractLocalizedEntity,
        SpyProductAbstractStorage $spyProductStorageEntity,
        $storeName,
        $localeName
    ) {
        $productAbstractStorageTransfer = $this->mapToProductAbstractStorageTransfer(
            $productAbstractLocalizedEntity,
            new ProductAbstractStorageTransfer()
        );

        $spyProductStorageEntity
            ->setFkProductAbstract($productAbstractLocalizedEntity['SpyProductAbstract'][static::COL_ID_PRODUCT_ABSTRACT])
            ->setData($productAbstractStorageTransfer->toArray())
            ->setStore($storeName)
            ->setLocale($localeName)
            ->save();
    }

    /**
     * @param array $productAbstractLocalizedEntity
     *
     * @return bool
     */
    protected function isActive(array $productAbstractLocalizedEntity)
    {
        foreach ($productAbstractLocalizedEntity['SpyProductAbstract']['SpyProducts'] as $productEntity) {
            if ($productEntity['is_active']) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array $productAbstractLocalizedEntity
     * @param \Generated\Shared\Transfer\ProductAbstractStorageTransfer $productAbstractStorageTransfer
     *
     * @return \Generated\Shared\Transfer\ProductAbstractStorageTransfer
     */
    protected function mapToProductAbstractStorageTransfer(
        array $productAbstractLocalizedEntity,
        ProductAbstractStorageTransfer $productAbstractStorageTransfer
    ) {
        $attributes = $this->getProductAbstractAttributes($productAbstractLocalizedEntity);
        $attributeMap = $this->getFactory()->createAttributeMapHelper()->generateAttributeMap(
            $productAbstractLocalizedEntity[static::COL_FK_PRODUCT_ABSTRACT],
            $productAbstractLocalizedEntity['Locale']['id_locale']
        );
        $productAbstractEntity = $productAbstractLocalizedEntity['SpyProductAbstract'];
        unset($productAbstractLocalizedEntity['attributes']);
        unset($productAbstractEntity['attributes']);

        $productAbstractStorageTransfer
            ->fromArray($productAbstractLocalizedEntity, true)
            ->fromArray($productAbstractEntity, true)
            ->setAttributes($attributes)
            ->setAttributeMap($attributeMap)
            ->setSuperAttributesDefinition($this->getSuperAttributeKeys($attributes));

        return $productAbstractStorageTransfer;
    }

    /**
     * @param array $productAbstractLocalizedEntity
     *
     * @return array
     */
    protected function getProductAbstractAttributes(array $productAbstractLocalizedEntity)
    {
        $productAbstractDecodedAttributes = $this->getFactory()->getProductFacade()->decodeProductAttributes(
            $productAbstractLocalizedEntity['SpyProductAbstract']['attributes']
        );
        $productAbstractLocalizedDecodedAttributes = $this->getFactory()->getProductFacade()->decodeProductAttributes(
            $productAbstractLocalizedEntity['attributes']
        );

        $rawProductAttributesTransfer = (new RawProductAttributesTransfer())
            ->setAbstractAttributes($productAbstractDecodedAttributes)
            ->setAbstractLocalizedAttributes($productAbstractLocalizedDecodedAttributes);

        $attributes = $this->getFactory()->getProductFacade()->combineRawProductAttributes($rawProductAttributesTransfer);

        $attributes = array_filter($attributes, function ($attributeKey) {
            return !empty($attributeKey);
        }, ARRAY_FILTER_USE_KEY);

        return $attributes;
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
     * @param array $productAbstractIds
     *
     * @return array
     */
    protected function findProductAbstractLocalizedEntities(array $productAbstractIds)
    {
        return $this->getQueryContainer()->queryProductAbstractByIds($productAbstractIds)->find()->getData();
    }

    /**
     * @param int[] $productAbstractIds
     *
     * @return \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage[]
     */
    protected function findProductAbstractStorageEntities(array $productAbstractIds)
    {
        return $this->getQueryContainer()->queryProductAbstractStorageByIds($productAbstractIds)->find()->getArrayCopy();
    }

    /**
     * @param \Orm\Zed\ProductStorage\Persistence\SpyProductAbstractStorage[] $productAbstractStorageEntities
     *
     * @return array
     */
    protected function mapProductAbstractStorageEntities(array $productAbstractStorageEntities)
    {
        $map = [];
        foreach ($productAbstractStorageEntities as $entity) {
            $map[$entity->getFkProductAbstract()][$entity->getStore()][$entity->getLocale()] = $entity;
        }

        return $map;
    }
}
