<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockStorage\Communication\Plugin\Event\Listener;

use Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage;
use Spryker\Shared\Kernel\Store;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\CmsBlockStorage\Communication\CmsBlockStorageCommunicationFactory getFactory()
 * @method \Spryker\Zed\CmsBlockStorage\Persistence\CmsBlockStorageQueryContainerInterface getQueryContainer()
 */
class AbstractCmsBlockStorageListener extends AbstractPlugin
{
    use DatabaseTransactionHandlerTrait;

    const RELATION_CMS_BLOCK_STORES = 'SpyCmsBlockStores';
    const RELATION_STORE = 'SpyStore';
    const COLUMN_ID_CMS_BLOCK = 'id_cms_block';
    const COLUMN_STORE_NAME = 'name';
    const COLUMN_CMS_BLOCK_NAME = 'name';
    const COLUMN_CMS_BLOCK_IS_ACTIVE = 'is_active';

    const CMS_BLOCK_ENTITY = 'CMS_BLOCK_ENTITY';
    const CMS_BLOCK_STORAGE_ENTITY = 'CMS_BLOCK_STORAGE_ENTITY';
    const LOCALE_NAME = 'LOCALE_NAME';
    const STORE_NAME = 'STORE_NAME';

    /**
     * Specification:
     * - Aggregates all cms block related data for given cms block IDs
     * - Saves aggregated data to database
     * - Sends aggregated data to synchronization queue
     *
     * @param array $cmsBlockIds
     *
     * @return void
     */
    protected function publish(array $cmsBlockIds)
    {
        $cmsBlockEntities = $this->findCmsBlockEntities($cmsBlockIds);
        $cmsBlockStorageEntities = $this->findCmsBlockStorageEntities($cmsBlockIds);

        if (!$cmsBlockEntities) {
            $this->deleteStorageEntities($cmsBlockStorageEntities);

            return;
        }

        $this->storeData($cmsBlockEntities, $cmsBlockStorageEntities);
    }

    /**
     * Specification:
     * - Delete cms stored block data for given cms block IDs
     * - Sends deleted keys to synchronization queue
     *
     * @param array $cmsBlockIds
     *
     * @return void
     */
    protected function unpublish(array $cmsBlockIds)
    {
        $cmsBlockStorageEntities = $this->findCmsBlockStorageEntities($cmsBlockIds);

        $this->deleteStorageEntities($cmsBlockStorageEntities);
    }

    /**
     * @param array $cmsBlockEntities
     * @param \Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage[] $cmsBlockStorageEntities
     *
     * @return void
     */
    protected function storeData(array $cmsBlockEntities, array $cmsBlockStorageEntities)
    {
        $pairedEntities = $this->pairCmsBlockEntitiesWithCmsBlockStorageEntities(
            $cmsBlockEntities,
            $cmsBlockStorageEntities
        );

        foreach ($pairedEntities as $pair) {
            $cmsBlockEntity = $pair[static::CMS_BLOCK_ENTITY];
            $cmsBlockStorageEntity = $pair[static::CMS_BLOCK_STORAGE_ENTITY];

            if ($cmsBlockEntity === null || !$cmsBlockEntity[static::COLUMN_CMS_BLOCK_IS_ACTIVE]) {
                $this->deleteStorageEntity($cmsBlockStorageEntity);

                continue;
            }

            $this->updateStoreData($cmsBlockEntity, $cmsBlockStorageEntity, $pair[static::STORE_NAME], $pair[static::LOCALE_NAME]);
        }
    }

    /**
     * @param \Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage[] $cmsBlockStorageEntities
     *
     * @return void
     */
    protected function deleteStorageEntities(array $cmsBlockStorageEntities)
    {
        foreach ($cmsBlockStorageEntities as $cmsBlockStorageEntity) {
            $cmsBlockStorageEntity->delete();
        }
    }

    /**
     * @param \Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage $cmsBlockStorageEntity
     *
     * @return void
     */
    protected function deleteStorageEntity(SpyCmsBlockStorage $cmsBlockStorageEntity)
    {
        if (!$cmsBlockStorageEntity->isNew()) {
            $cmsBlockStorageEntity->delete();
        }
    }

    /**
     * @param array $cmsBlockEntity
     * @param \Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage $cmsBlockStorageEntity
     * @param string $storeName
     * @param string $localeName
     *
     * @return void
     */
    protected function updateStoreData(array $cmsBlockEntity, SpyCmsBlockStorage $cmsBlockStorageEntity, $storeName, $localeName)
    {
        $cmsBlockEntity = $this->getFactory()->getUtilSanitize()->arrayFilterRecursive($cmsBlockEntity);
        foreach ($this->getFactory()->getContentWidgetDataExpanderPlugins() as $contentWidgetDataExpanderPlugin) {
            $cmsBlockEntity = $contentWidgetDataExpanderPlugin->expand($cmsBlockEntity, $localeName);
        }

        $cmsBlockStorageEntity
            ->setData($cmsBlockEntity)
            ->setFkCmsBlock($cmsBlockEntity[static::COLUMN_ID_CMS_BLOCK])
            ->setLocale($localeName)
            ->setStore($storeName)
            ->setName($cmsBlockEntity[static::COLUMN_CMS_BLOCK_NAME])
            ->save();
    }

    /**
     * - Returns a paired array with all provided entities.
     * - CmsBlockEntities without CmsBlockStorageEntity are paired with a newly created CmsBlockStorageEntity.
     * - CmsBlockStorageEntities without CmsBlockEntity (left outs) are paired with NULL.
     * - CmsBlockEntities are paired multiple times per locale and per store.
     *
     * @param array $cmsBlockEntities
     * @param array $cmsBlockStorageEntities
     *
     * @return array
     */
    protected function pairCmsBlockEntitiesWithCmsBlockStorageEntities(array $cmsBlockEntities, array $cmsBlockStorageEntities)
    {
        $mappedCmsBlockStorageEntities = $this->mapCmsBlockStorageEntities($cmsBlockStorageEntities);
        $localeNames = $this->getStore()->getLocales();

        $pairs = [];
        foreach ($cmsBlockEntities as $cmsBlockEntity) {
            list($pairs, $mappedCmsBlockStorageEntities) = $this->pairCmsBlockEntityWithCmsBlockStorageEntitiesByLocalesAndStores(
                $cmsBlockEntity[static::COLUMN_ID_CMS_BLOCK],
                $localeNames,
                $cmsBlockEntity[static::RELATION_CMS_BLOCK_STORES],
                $cmsBlockEntity,
                $mappedCmsBlockStorageEntities,
                $pairs
            );
        }

        $pairs = $this->pairRemainingCmsBlockStorageEntities($mappedCmsBlockStorageEntities, $pairs);

        return $pairs;
    }

    /**
     * @param \Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage[] $cmsBlockStorageEntities
     *
     * @return array
     */
    protected function mapCmsBlockStorageEntities(array $cmsBlockStorageEntities)
    {
        $mappedCmsBlockStorageEntities = [];
        foreach ($cmsBlockStorageEntities as $entity) {
            $mappedCmsBlockStorageEntities[$entity->getFkCmsBlock()][$entity->getLocale()][$entity->getStore()] = $entity;
        }
        
        return $mappedCmsBlockStorageEntities;
    }

    /**
     * @param array $cmsBlockIds
     *
     * @return array
     */
    protected function findCmsBlockEntities(array $cmsBlockIds)
    {
        return $this->getQueryContainer()->queryBlockWithRelationsByIds($cmsBlockIds)->find()->getData();
    }

    /**
     * @param array $cmsBlockIds
     *
     * @return \Orm\Zed\CmsBlockStorage\Persistence\SpyCmsBlockStorage[]
     */
    protected function findCmsBlockStorageEntities(array $cmsBlockIds)
    {
        return $this->getQueryContainer()->queryCmsBlockStorageEntities($cmsBlockIds)->find()->getArrayCopy();
    }

    /**
     * @return \Spryker\Shared\Kernel\Store
     */
    protected function getStore()
    {
        return Store::getInstance();
    }

    /**
     * @param array $mappedCmsBlockStorageEntities
     * @param array $pairs
     *
     * @return array
     */
    protected function pairRemainingCmsBlockStorageEntities(array $mappedCmsBlockStorageEntities, array $pairs)
    {
        array_walk_recursive($mappedCmsBlockStorageEntities, function (SpyCmsBlockStorage $cmsBlockStorageEntity) use (&$pairs) {
            $pairs[] = [
                static::CMS_BLOCK_ENTITY => null,
                static::CMS_BLOCK_STORAGE_ENTITY => $cmsBlockStorageEntity,
                static::LOCALE_NAME => $cmsBlockStorageEntity->getLocale(),
                static::STORE_NAME => $cmsBlockStorageEntity->getStore(),
            ];
        });

        return $pairs;
    }

    /**
     * @param int $idCmsBlock
     * @param string[] $localeNames
     * @param array $cmsBlockStores
     * @param array $cmsBlockEntity
     * @param array $mappedCmsBlockStorageEntities
     * @param array $pairs
     *
     * @return array
     */
    protected function pairCmsBlockEntityWithCmsBlockStorageEntitiesByLocalesAndStores(
        $idCmsBlock,
        array $localeNames,
        array $cmsBlockStores,
        array $cmsBlockEntity,
        array $mappedCmsBlockStorageEntities,
        array $pairs
    ) {
        foreach ($localeNames as $localeName) {
            foreach ($cmsBlockStores as $cmsBlockStore) {
                $storeName = $cmsBlockStore[static::RELATION_STORE][static::COLUMN_STORE_NAME];

                $cmsBlockStorageEntity = isset($mappedCmsBlockStorageEntities[$idCmsBlock][$localeName][$storeName]) ?
                    $mappedCmsBlockStorageEntities[$idCmsBlock][$localeName][$storeName] :
                    new SpyCmsBlockStorage();

                $pairs[] = [
                    static::CMS_BLOCK_ENTITY => $cmsBlockEntity,
                    static::CMS_BLOCK_STORAGE_ENTITY => $cmsBlockStorageEntity,
                    static::LOCALE_NAME => $localeName,
                    static::STORE_NAME => $storeName,
                ];

                unset($mappedCmsBlockStorageEntities[$idCmsBlock][$localeName][$storeName]);
            }
        }

        return [$pairs, $mappedCmsBlockStorageEntities];
    }
}
