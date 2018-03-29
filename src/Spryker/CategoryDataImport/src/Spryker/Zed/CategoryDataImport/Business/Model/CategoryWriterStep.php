<?php

/**
 * MIT License
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CategoryDataImport\Business\Model;

use Exception;
use Orm\Zed\Category\Persistence\SpyCategory;
use Orm\Zed\Category\Persistence\SpyCategoryAttributeQuery;
use Orm\Zed\Category\Persistence\SpyCategoryClosureTableQuery;
use Orm\Zed\Category\Persistence\SpyCategoryNode;
use Orm\Zed\Category\Persistence\SpyCategoryNodeQuery;
use Orm\Zed\Category\Persistence\SpyCategoryQuery;
use Orm\Zed\Category\Persistence\SpyCategoryTemplateQuery;
use Orm\Zed\Url\Persistence\SpyUrlQuery;
use Spryker\Zed\Category\Dependency\CategoryEvents;
use Spryker\Zed\CategoryDataImport\Business\Model\Repository\CategoryRepositoryInterface;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\AddLocalesStep;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\DataImportStepInterface;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\LocalizedAttributesExtractorStep;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\PublishAwareStep;
use Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface;
use Spryker\Zed\Url\Dependency\UrlEvents;

/**
 * @SuppressWarnings(PHPMD.CouplingBetweenObjects)
 */
class CategoryWriterStep extends PublishAwareStep implements DataImportStepInterface
{
    const BULK_SIZE = 100;

    const KEY_NAME = 'name';
    const KEY_META_TITLE = 'meta_title';
    const KEY_META_DESCRIPTION = 'meta_description';
    const KEY_META_KEYWORDS = 'meta_keywords';
    const KEY_CATEGORY_KEY = 'category_key';
    const KEY_PARENT_CATEGORY_KEY = 'parent_category_key';
    const KEY_TEMPLATE_NAME = 'template_name';

    /**
     * @var \Spryker\Zed\CategoryDataImport\Business\Model\Repository\CategoryRepositoryInterface
     */
    protected $categoryRepository;

    /**
     * @param \Spryker\Zed\CategoryDataImport\Business\Model\Repository\CategoryRepositoryInterface $categoryRepository
     */
    public function __construct(CategoryRepositoryInterface $categoryRepository)
    {
        $this->categoryRepository = $categoryRepository;
    }

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return void
     */
    public function execute(DataSetInterface $dataSet)
    {
        $categoryEntity = $this->findOrCreateCategory($dataSet);
        $this->findOrCreateAttributes($categoryEntity, $dataSet);
        $categoryNodeEntity = $this->findOrCreateNode($categoryEntity, $dataSet);

        $this->categoryRepository->addCategory($categoryEntity, $categoryNodeEntity);
    }

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return \Orm\Zed\Category\Persistence\SpyCategory
     */
    protected function findOrCreateCategory(DataSetInterface $dataSet)
    {
        $categoryEntity = SpyCategoryQuery::create()
            ->filterByCategoryKey($dataSet[static::KEY_CATEGORY_KEY])
            ->findOneOrCreate();

        $categoryEntity->fromArray($dataSet->getArrayCopy());

        if (!empty($dataSet[static::KEY_TEMPLATE_NAME])) {
            $categoryTemplateEntity = SpyCategoryTemplateQuery::create()->findOneByName($dataSet[static::KEY_TEMPLATE_NAME]);
            $categoryEntity->setFkCategoryTemplate($categoryTemplateEntity->getIdCategoryTemplate());
        }

        if ($categoryEntity->isNew() || $categoryEntity->isModified()) {
            $categoryEntity->save();
        }

        return $categoryEntity;
    }

    /**
     * @param \Orm\Zed\Category\Persistence\SpyCategory $categoryEntity
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return void
     */
    protected function findOrCreateAttributes(SpyCategory $categoryEntity, DataSetInterface $dataSet)
    {
        $localizedAttributeCollection = $dataSet[LocalizedAttributesExtractorStep::KEY_LOCALIZED_ATTRIBUTES];
        foreach ($localizedAttributeCollection as $idLocale => $localizedAttributes) {
            $categoryAttributeEntity = SpyCategoryAttributeQuery::create()
                ->filterByCategory($categoryEntity)
                ->filterByFkLocale($idLocale)
                ->findOneOrCreate();

            $categoryAttributeEntity->fromArray($localizedAttributes);

            if ($categoryAttributeEntity->isNew() || $categoryAttributeEntity->isModified()) {
                $categoryAttributeEntity->save();
            }
        }
    }

    /**
     * @param \Orm\Zed\Category\Persistence\SpyCategory $categoryEntity
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return \Orm\Zed\Category\Persistence\SpyCategoryNode
     */
    protected function findOrCreateNode(SpyCategory $categoryEntity, DataSetInterface $dataSet)
    {
        $categoryNodeEntity = SpyCategoryNodeQuery::create()
            ->filterByCategory($categoryEntity)
            ->findOneOrCreate();

        if (!empty($dataSet[static::KEY_PARENT_CATEGORY_KEY])) {
            $idParentCategoryNode = $this->categoryRepository->getIdCategoryNodeByCategoryKey($dataSet[static::KEY_PARENT_CATEGORY_KEY]);
            $categoryNodeEntity->setFkParentCategoryNode($idParentCategoryNode);
        }

        $categoryNodeEntity->fromArray($dataSet->getArrayCopy());

        if ($categoryNodeEntity->isNew() || $categoryNodeEntity->isModified()) {
            $categoryNodeEntity->save();
        }

        $this->addToClosureTable($categoryNodeEntity);
        $this->addPublishEvents(CategoryEvents::CATEGORY_NODE_PUBLISH, $categoryNodeEntity->getIdCategoryNode());

        foreach ($categoryEntity->getAttributes() as $categoryAttributesEntity) {
            $idLocale = $categoryAttributesEntity->getFkLocale();
            $languageIdentifier = $this->getLanguageIdentifier($idLocale, $dataSet);
            $urlPathParts = [$languageIdentifier];
            if (!$categoryNodeEntity->getIsRoot()) {
                $parentUrl = $this->categoryRepository->getParentUrl(
                    $dataSet[static::KEY_PARENT_CATEGORY_KEY],
                    $idLocale
                );

                $urlPathParts = explode('/', ltrim($parentUrl, '/'));
                $urlPathParts[] = $categoryAttributesEntity->getName();
            }

            if ($categoryNodeEntity->getIsRoot()) {
                $this->addPublishEvents(CategoryEvents::CATEGORY_TREE_PUBLISH, $categoryNodeEntity->getIdCategoryNode());
            }

            $convertCallback = function ($value) {
                return mb_strtolower(str_replace(' ', '-', $value));
            };
            $urlPathParts = array_map($convertCallback, $urlPathParts);
            $url = '/' . implode('/', $urlPathParts);

            $urlEntity = SpyUrlQuery::create()
                ->filterByFkLocale($idLocale)
                ->filterByFkResourceCategorynode($categoryNodeEntity->getIdCategoryNode())
                ->findOneOrCreate();

            $urlEntity
                ->setUrl($url);

            if ($urlEntity->isNew() || $urlEntity->isModified()) {
                $urlEntity->save();
                $this->addPublishEvents(UrlEvents::URL_PUBLISH, $urlEntity->getIdUrl());
            }
        }

        return $categoryNodeEntity;
    }

    /**
     * @param int $idLocale
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @throws \Exception
     *
     * @return string
     */
    protected function getLanguageIdentifier($idLocale, DataSetInterface $dataSet)
    {
        foreach ($dataSet[AddLocalesStep::KEY_LOCALES] as $localeName => $localeId) {
            if ($idLocale === $localeId) {
                return mb_substr($localeName, 0, 2);
            }
        }

        throw new Exception(sprintf('Could not extract language identifier for idLocale "%s"', $idLocale));
    }

    /**
     * @param \Orm\Zed\Category\Persistence\SpyCategoryNode $categoryNodeEntity
     *
     * @return void
     */
    protected function addToClosureTable(SpyCategoryNode $categoryNodeEntity)
    {
        if ($categoryNodeEntity->getFkParentCategoryNode() !== null) {
            $categoryClosureEntityCollection = SpyCategoryClosureTableQuery::create()
                ->findByFkCategoryNodeDescendant($categoryNodeEntity->getFkParentCategoryNode());

            foreach ($categoryClosureEntityCollection as $categoryClosureEntity) {
                $newCategoryClosureTableEntity = SpyCategoryClosureTableQuery::create()
                    ->filterByFkCategoryNode($categoryClosureEntity->getFkCategoryNode())
                    ->filterByFkCategoryNodeDescendant($categoryNodeEntity->getIdCategoryNode())
                    ->findOneOrCreate();

                $newCategoryClosureTableEntity
                    ->setDepth($categoryClosureEntity->getDepth() + 1);

                if ($newCategoryClosureTableEntity->isNew() || $newCategoryClosureTableEntity->isModified()) {
                    $newCategoryClosureTableEntity->save();
                }
            }
        }

        $categoryClosureTableEntity = SpyCategoryClosureTableQuery::create()
            ->filterByFkCategoryNode($categoryNodeEntity->getIdCategoryNode())
            ->filterByFkCategoryNodeDescendant($categoryNodeEntity->getIdCategoryNode())
            ->findOneOrCreate();

        $categoryClosureTableEntity
            ->setDepth(0);

        if ($categoryClosureTableEntity->isNew() || $categoryClosureTableEntity->isModified()) {
            $categoryClosureTableEntity->save();
        }
    }
}
