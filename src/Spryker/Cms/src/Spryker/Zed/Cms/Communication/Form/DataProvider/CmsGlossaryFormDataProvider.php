<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Cms\Communication\Form\DataProvider;

use Spryker\Zed\Cms\Communication\Form\CmsGlossaryForm;
use Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface;

class CmsGlossaryFormDataProvider
{
    /**
     * @var \Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface
     */
    protected $cmsQueryContainer;

    /**
     * @param \Spryker\Zed\Cms\Persistence\CmsQueryContainerInterface $cmsQueryContainer
     */
    public function __construct(CmsQueryContainerInterface $cmsQueryContainer)
    {
        $this->cmsQueryContainer = $cmsQueryContainer;
    }

    /**
     * @param int $idPage
     * @param int|null $idMapping
     * @param string|null $placeholder
     * @param int|null $fkLocale
     *
     * @return array
     */
    public function getData(int $idPage, ?int $idMapping = null, ?string $placeholder = null, ?int $fkLocale = null): array
    {
        $formItems = [
            CmsGlossaryForm::FIELD_FK_PAGE => $idPage,
            CmsGlossaryForm::FIELD_ID_KEY_MAPPING => $idMapping,
            CmsGlossaryForm::FIELD_FK_LOCALE => $fkLocale,
        ];

        if ($placeholder !== null) {
            $formItems[CmsGlossaryForm::FIELD_PLACEHOLDER] = $placeholder;
        }

        if ($idMapping !== null) {
            $glossaryMapping = $this
                ->cmsQueryContainer
                ->queryGlossaryKeyMappingWithKeyById($idMapping)
                ->findOne();

            if ($glossaryMapping) {
                $formItems[CmsGlossaryForm::FIELD_PLACEHOLDER] = $glossaryMapping->getPlaceholder();
                $formItems[CmsGlossaryForm::FIELD_GLOSSARY_KEY] = $glossaryMapping->getKeyname();
                $formItems[CmsGlossaryForm::FIELD_TRANSLATION] = $glossaryMapping->getTrans();
            }
        }

        return $formItems;
    }
}
