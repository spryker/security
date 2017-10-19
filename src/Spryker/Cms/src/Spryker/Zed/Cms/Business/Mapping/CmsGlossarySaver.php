<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Cms\Business\Mapping;

use Exception;
use Generated\Shared\Transfer\CmsGlossaryAttributesTransfer;
use Generated\Shared\Transfer\CmsGlossaryTransfer;
use Generated\Shared\Transfer\CmsPlaceholderTranslationTransfer;
use Generated\Shared\Transfer\KeyTranslationTransfer;
use Orm\Zed\Cms\Persistence\Map\SpyCmsGlossaryKeyMappingTableMap;
use Orm\Zed\Cms\Persistence\SpyCmsGlossaryKeyMapping;
use Spryker\Zed\Cms\Business\Exception\MappingAmbiguousException;
use Spryker\Zed\Cms\Business\Exception\MissingGlossaryKeyMappingException;
use Spryker\Zed\Cms\Dependency\Facade\CmsToGlossaryInterface;
use Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface;
use Throwable;

class CmsGlossarySaver implements CmsGlossarySaverInterface
{
    const DEFAULT_TRANSLATION = '';

    /**
     * @var \Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface
     */
    protected $cmsQueryContainer;

    /**
     * @var \Spryker\Zed\Cms\Dependency\Facade\CmsToGlossaryInterface
     */
    protected $glossaryFacade;

    /**
     * @var \Spryker\Zed\Cms\Business\Mapping\CmsGlossaryKeyGeneratorInterface
     */
    protected $cmsGlossaryKeyGenerator;

    /**
     * @param \Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface $cmsQueryContainer
     * @param \Spryker\Zed\Cms\Dependency\Facade\CmsToGlossaryInterface $glossaryFacade
     * @param \Spryker\Zed\Cms\Business\Mapping\CmsGlossaryKeyGeneratorInterface $cmsGlossaryKeyGenerator
     */
    public function __construct(
        CmsQueryContainerInterface $cmsQueryContainer,
        CmsToGlossaryInterface $glossaryFacade,
        CmsGlossaryKeyGeneratorInterface $cmsGlossaryKeyGenerator
    ) {
        $this->cmsQueryContainer = $cmsQueryContainer;
        $this->glossaryFacade = $glossaryFacade;
        $this->cmsGlossaryKeyGenerator = $cmsGlossaryKeyGenerator;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsGlossaryTransfer $cmsGlossaryTransfer
     *
     * @throws \Exception
     * @throws \Throwable
     *
     * @return \Generated\Shared\Transfer\CmsGlossaryTransfer
     */
    public function saveCmsGlossary(CmsGlossaryTransfer $cmsGlossaryTransfer)
    {
        try {
            $this->cmsQueryContainer->getConnection()->beginTransaction();

            foreach ($cmsGlossaryTransfer->getGlossaryAttributes() as $glossaryAttributesTransfer) {
                $translationKey = $this->resolveTranslationKey($glossaryAttributesTransfer);
                $glossaryAttributesTransfer->setTranslationKey($translationKey);

                $this->translatePlaceholder($glossaryAttributesTransfer, $translationKey);

                $idCmsGlossaryMapping = $this->saveCmsGlossaryKeyMapping($glossaryAttributesTransfer);
                $glossaryAttributesTransfer->setFkCmsGlossaryMapping($idCmsGlossaryMapping);
            }
            $this->cmsQueryContainer->getConnection()->commit();
        } catch (Exception $exception) {
            $this->cmsQueryContainer->getConnection()->rollBack();
            throw $exception;
        } catch (Throwable $exception) {
            $this->cmsQueryContainer->getConnection()->rollBack();
            throw $exception;
        }

        return $cmsGlossaryTransfer;
    }

    /**
     * @param int $idCmsPage
     *
     * @return void
     */
    public function deleteCmsGlossary($idCmsPage)
    {
        $idGlossaryKeys = $this->cmsQueryContainer->queryGlossaryKeyMappingsByPageId($idCmsPage)
            ->select(SpyCmsGlossaryKeyMappingTableMap::COL_FK_GLOSSARY_KEY)
            ->find()
            ->toArray();

        if (empty($idGlossaryKeys)) {
            return;
        }

        $this->cmsQueryContainer->queryGlossaryKeyMappingsByFkGlossaryKeys($idGlossaryKeys)->delete();
        $this->glossaryFacade->deleteTranslationsByFkKeys($idGlossaryKeys);
        $this->glossaryFacade->deleteKeys($idGlossaryKeys);
    }

    /**
     * @param \Generated\Shared\Transfer\CmsGlossaryAttributesTransfer $glossaryAttributesTransfer
     *
     * @return int
     */
    protected function saveCmsGlossaryKeyMapping(CmsGlossaryAttributesTransfer $glossaryAttributesTransfer)
    {
        if ($glossaryAttributesTransfer->getFkCmsGlossaryMapping() === null) {
            return $this->createPageKeyMapping($glossaryAttributesTransfer);
        } else {
            return $this->updatePageKeyMapping($glossaryAttributesTransfer);
        }
    }

    /**
     * @param \Generated\Shared\Transfer\CmsGlossaryAttributesTransfer $cmsGlossaryAttributesTransfer
     *
     * @return int
     */
    protected function createPageKeyMapping(CmsGlossaryAttributesTransfer $cmsGlossaryAttributesTransfer)
    {
        $this->checkPagePlaceholderNotAmbiguous(
            $cmsGlossaryAttributesTransfer->getFkPage(),
            $cmsGlossaryAttributesTransfer->getPlaceholder()
        );

        $cmsGlossaryKeyMappingEntity = $this->createCmsGlossaryKeyMappingEntity();
        $cmsGlossaryKeyMappingEntity->fromArray($cmsGlossaryAttributesTransfer->toArray());

        $cmsGlossaryKeyMappingEntity->save();

        return $cmsGlossaryKeyMappingEntity->getPrimaryKey();
    }

    /**
     * @param \Generated\Shared\Transfer\CmsGlossaryAttributesTransfer $cmsGlossaryAttributesTransfer
     *
     * @return int
     */
    protected function updatePageKeyMapping(CmsGlossaryAttributesTransfer $cmsGlossaryAttributesTransfer)
    {
        $glossaryKeyMappingEntity = $this->getGlossaryKeyMappingById($cmsGlossaryAttributesTransfer->getFkCmsGlossaryMapping());
        $glossaryKeyMappingEntity->fromArray($cmsGlossaryAttributesTransfer->modifiedToArray());

        if (!$glossaryKeyMappingEntity->isModified()) {
            return $glossaryKeyMappingEntity->getPrimaryKey();
        }

        $isPlaceholderModified = $glossaryKeyMappingEntity->isColumnModified(SpyCmsGlossaryKeyMappingTableMap::COL_PLACEHOLDER);
        $isPageIdModified = $glossaryKeyMappingEntity->isColumnModified(SpyCmsGlossaryKeyMappingTableMap::COL_FK_PAGE);

        if ($isPlaceholderModified || $isPageIdModified) {
            $this->checkPagePlaceholderNotAmbiguous(
                $cmsGlossaryAttributesTransfer->getFkPage(),
                $cmsGlossaryAttributesTransfer->getPlaceholder()
            );
        }

        $glossaryKeyMappingEntity->save();

        return $glossaryKeyMappingEntity->getPrimaryKey();
    }

    /**
     * @param int $idMapping
     *
     * @throws \Spryker\Zed\Cms\Business\Exception\MissingGlossaryKeyMappingException
     *
     * @return \Orm\Zed\Cms\Persistence\SpyCmsGlossaryKeyMapping
     */
    protected function getGlossaryKeyMappingById($idMapping)
    {
        $mappingEntity = $this->findGlossaryKeyMappingEntityById($idMapping);

        if (!$mappingEntity) {
            throw new MissingGlossaryKeyMappingException(sprintf('Tried to retrieve a missing glossary key mapping with id %s', $idMapping));
        }

        return $mappingEntity;
    }

    /**
     * @param int $idPage
     * @param string $placeholder
     *
     * @throws \Spryker\Zed\Cms\Business\Exception\MappingAmbiguousException
     *
     * @return void
     */
    protected function checkPagePlaceholderNotAmbiguous($idPage, $placeholder)
    {
        if ($this->hasPagePlaceholderMapping($idPage, $placeholder)) {
            throw new MappingAmbiguousException(sprintf('Tried to create an ambiguous mapping for placeholder %s on page %s', $placeholder, $idPage));
        }
    }

    /**
     * @param int $idPage
     * @param string $placeholder
     *
     * @return bool
     */
    protected function hasPagePlaceholderMapping($idPage, $placeholder)
    {
        $mappingCount = $this->cmsQueryContainer
            ->queryGlossaryKeyMapping($idPage, $placeholder)
            ->count();

        return $mappingCount > 0;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsGlossaryAttributesTransfer $glossaryAttributesTransfer
     *
     * @return string
     */
    protected function resolveTranslationKey(CmsGlossaryAttributesTransfer $glossaryAttributesTransfer)
    {
        $translationKey = $glossaryAttributesTransfer->getTranslationKey();
        if (!$glossaryAttributesTransfer->getTranslationKey()) {
            $translationKey = $this->cmsGlossaryKeyGenerator->generateGlossaryKeyName(
                $glossaryAttributesTransfer->getFkPage(),
                $glossaryAttributesTransfer->getTemplateName(),
                $glossaryAttributesTransfer->getPlaceholder()
            );
        }
        return $translationKey;
    }

    /**
     * @param \Generated\Shared\Transfer\CmsGlossaryAttributesTransfer $glossaryAttributesTransfer
     * @param string $translationKey
     *
     * @return void
     */
    protected function translatePlaceholder(CmsGlossaryAttributesTransfer $glossaryAttributesTransfer, $translationKey)
    {
        foreach ($glossaryAttributesTransfer->getTranslations() as $glossaryTranslationTransfer) {
            $this->setDefaultTranslation($glossaryTranslationTransfer);
            $keyTranslationTransfer = $this->createTranslationTransfer($translationKey, $glossaryTranslationTransfer);
            $this->glossaryFacade->saveGlossaryKeyTranslations($keyTranslationTransfer);
        }

        $glossaryKeyEntity = $this->findGlossaryKeyEntityByTranslationKey($translationKey);
        if ($glossaryKeyEntity === null) {
            return;
        }

        $glossaryAttributesTransfer->setFkGlossaryKey($glossaryKeyEntity->getIdGlossaryKey());
    }

    /**
     * @param string $translationKey
     * @param \Generated\Shared\Transfer\CmsPlaceholderTranslationTransfer $glossaryTranslationTransfer
     *
     * @return \Generated\Shared\Transfer\KeyTranslationTransfer
     */
    protected function createTranslationTransfer($translationKey, CmsPlaceholderTranslationTransfer $glossaryTranslationTransfer)
    {
        $keyTranslationTransfer = new KeyTranslationTransfer();
        $keyTranslationTransfer->setGlossaryKey($translationKey);

        $keyTranslationTransfer->setLocales([
            $glossaryTranslationTransfer->getLocaleName() => $glossaryTranslationTransfer->getTranslation(),
        ]);

        return $keyTranslationTransfer;
    }

    /**
     * @return \Orm\Zed\Cms\Persistence\SpyCmsGlossaryKeyMapping
     */
    protected function createCmsGlossaryKeyMappingEntity()
    {
        return new SpyCmsGlossaryKeyMapping();
    }

    /**
     * @param string $translationKey
     *
     * @return \Orm\Zed\Glossary\Persistence\SpyGlossaryKey
     */
    protected function findGlossaryKeyEntityByTranslationKey($translationKey)
    {
        return $this->cmsQueryContainer
            ->queryKey($translationKey)
            ->findOne();
    }

    /**
     * @param int $idMapping
     *
     * @return \Orm\Zed\Cms\Persistence\SpyCmsGlossaryKeyMapping
     */
    protected function findGlossaryKeyMappingEntityById($idMapping)
    {
        return $this->cmsQueryContainer
            ->queryGlossaryKeyMappingById($idMapping)
            ->findOne();
    }

    /**
     * @param \Generated\Shared\Transfer\CmsPlaceholderTranslationTransfer $glossaryTranslationTransfer
     *
     * @return void
     */
    protected function setDefaultTranslation(CmsPlaceholderTranslationTransfer $glossaryTranslationTransfer)
    {
        if ($glossaryTranslationTransfer->getTranslation() === null) {
            $glossaryTranslationTransfer->setTranslation(static::DEFAULT_TRANSLATION);
        }
    }
}
