<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ContentBannerDataImport\Business\Model;

use Generated\Shared\Transfer\ContentBannerTermTransfer;
use Orm\Zed\Content\Persistence\SpyContent;
use Orm\Zed\Content\Persistence\SpyContentLocalizedQuery;
use Orm\Zed\Content\Persistence\SpyContentQuery;
use Spryker\Shared\ContentBanner\ContentBannerConfig;
use Spryker\Zed\Content\Dependency\ContentEvents;
use Spryker\Zed\ContentBannerDataImport\Business\Model\DataSet\ContentBannerDataSetInterface;
use Spryker\Zed\ContentBannerDataImport\Dependency\Service\ContentBannerDataImportToUtilEncodingInterface;
use Spryker\Zed\DataImport\Business\Exception\InvalidDataException;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\DataImportStepInterface;
use Spryker\Zed\DataImport\Business\Model\DataImportStep\PublishAwareStep;
use Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface;

class ContentBannerWriterStep extends PublishAwareStep implements DataImportStepInterface
{
    /**
     * @var \Spryker\Zed\ContentBannerDataImport\Dependency\Service\ContentBannerDataImportToUtilEncodingInterface
     */
    protected $utilEncoding;

    /**
     * @param \Spryker\Zed\ContentBannerDataImport\Dependency\Service\ContentBannerDataImportToUtilEncodingInterface $utilEncoding
     */
    public function __construct(ContentBannerDataImportToUtilEncodingInterface $utilEncoding)
    {
        $this->utilEncoding = $utilEncoding;
    }

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @return void
     */
    public function execute(DataSetInterface $dataSet): void
    {
        $contentBannerEntity = $this->saveContentBanner($dataSet);

        $this->saveContentLocalizedBannerTerms(
            $dataSet[ContentBannerDataSetInterface::CONTENT_LOCALIZED_BANNER_TERMS],
            $contentBannerEntity->getIdContent()
        );

        $this->addPublishEvents(
            ContentEvents::CONTENT_PUBLISH,
            $contentBannerEntity->getPrimaryKey()
        );
    }

    /**
     * @param \Spryker\Zed\DataImport\Business\Model\DataSet\DataSetInterface $dataSet
     *
     * @throws \Spryker\Zed\DataImport\Business\Exception\InvalidDataException
     *
     * @return \Orm\Zed\Content\Persistence\SpyContent
     */
    protected function saveContentBanner(DataSetInterface $dataSet): SpyContent
    {
        if (!trim($dataSet[ContentBannerDataSetInterface::CONTENT_BANNER_KEY])) {
            throw new InvalidDataException('Key field can\'t be empty.');
        }

        $contentBannerEntity = SpyContentQuery::create()
            ->filterByKey($dataSet[ContentBannerDataSetInterface::CONTENT_BANNER_KEY])
            ->findOneOrCreate();

        $contentBannerEntity->fromArray($dataSet->getArrayCopy());
        $contentBannerEntity->setContentTermKey(ContentBannerConfig::CONTENT_TERM_BANNER);
        $contentBannerEntity->setContentTypeKey(ContentBannerConfig::CONTENT_TYPE_BANNER);

        $contentBannerEntity->save();

        return $contentBannerEntity;
    }

    /**
     * @param array $localizedBannerTerms
     * @param int $idContentBannerTerm
     *
     * @throws \Spryker\Zed\DataImport\Business\Exception\InvalidDataException
     *
     * @return void
     */
    protected function saveContentLocalizedBannerTerms(array $localizedBannerTerms, int $idContentBannerTerm): void
    {
        SpyContentLocalizedQuery::create()
            ->filterByFkContent($idContentBannerTerm)
            ->find()
            ->delete();

        $defaultLocaleIsPresent = false;
        foreach ($localizedBannerTerms as $idLocale => $localizedBannerTerm) {
            if (!$idLocale) {
                $idLocale = null;
                $defaultLocaleIsPresent = true;
            }

            $localizedContentBannerEntity = SpyContentLocalizedQuery::create()
                ->filterByFkContent($idContentBannerTerm)
                ->filterByFkLocale($idLocale)
                ->findOneOrCreate();

            $localizedContentBannerEntity->setParameters(
                $this->getEncodedParameters($localizedBannerTerm)
            );

            $localizedContentBannerEntity->save();
        }

        if (!$defaultLocaleIsPresent) {
            throw new InvalidDataException('Default locale is absent');
        }
    }

    /**
     * @param \Generated\Shared\Transfer\ContentBannerTermTransfer $contentBannerTermTransfer
     *
     * @return string|null
     */
    protected function getEncodedParameters(ContentBannerTermTransfer $contentBannerTermTransfer): ?string
    {
        return $this->utilEncoding->encodeJson($contentBannerTermTransfer->toArray());
    }
}
