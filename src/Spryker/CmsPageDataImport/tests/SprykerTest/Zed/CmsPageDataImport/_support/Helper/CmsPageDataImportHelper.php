<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace SprykerTest\Zed\CmsPageDataImport\Helper;

use Codeception\Module;
use Orm\Zed\Cms\Persistence\SpyCmsPageQuery;
use Propel\Runtime\ActiveQuery\ModelCriteria;
use Propel\Runtime\Map\RelationMap;

class CmsPageDataImportHelper extends Module
{
    /**
     * @return void
     */
    public function ensureDatabaseTableCmsPageIsEmpty(): void
    {
        $cmsPageQuery = $this->getCmsPageQuery();

        $this->cleanTableRelations($cmsPageQuery);
    }

    /**
     * @param \Propel\Runtime\ActiveQuery\ModelCriteria $query
     * @param array $processedEntities
     *
     * @return void
     */
    protected function cleanTableRelations(ModelCriteria $query, array $processedEntities = []): void
    {
        $relations = $query->getTableMap()->getRelations();

        foreach ($relations as $relationMap) {
            $relationType = $relationMap->getType();
            $fullyQualifiedQueryModel = $relationMap->getLocalTable()->getClassname() . 'Query';
            if ($relationType == RelationMap::ONE_TO_MANY && !in_array($fullyQualifiedQueryModel, $processedEntities)) {
                $processedEntities[] = $fullyQualifiedQueryModel;
                $fullyQualifiedQueryModelObject = $fullyQualifiedQueryModel::create();
                $this->cleanTableRelations($fullyQualifiedQueryModelObject, $processedEntities);
            }
        }

        $query->deleteAll();
    }

    /**
     * @return void
     */
    public function assertDatabaseTableCmsPageContainsData(): void
    {
        $cmsPageQuery = $this->getCmsPageQuery();
        $this->assertTrue(($cmsPageQuery->count() > 0), 'Expected at least one entry in the database table but database table is empty.');
    }

    /**
     * @return \Orm\Zed\Cms\Persistence\SpyCmsPageQuery
     */
    protected function getCmsPageQuery(): SpyCmsPageQuery
    {
        return SpyCmsPageQuery::create();
    }
}
