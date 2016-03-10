<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Cms\Communication\Form\DataProvider;

use Spryker\Zed\Cms\Communication\Form\CmsPageForm;
use Spryker\Zed\Cms\Persistence\CmsQueryContainer;

class CmsPageFormDataProvider
{

    const ADD = 'add';
    const UPDATE = 'update';

    const PAGE = 'Page';

    const FIELD_URL = 'url';
    const FIELD_ID_CMS_PAGE = 'idCmsPage';
    const FIELD_FK_TEMPLATE = 'fkTemplate';
    const FIELD_CURRENT_TEMPLATE = 'cur_temp';
    const FIELD_IS_ACTIVE = 'is_active';

    /**
     * @var \Spryker\Zed\Cms\Persistence\CmsQueryContainer
     */
    protected $cmsQueryContainer;

    /**
     * @param \Spryker\Zed\Cms\Persistence\CmsQueryContainer $cmsQueryContainer
     */
    public function __construct(CmsQueryContainer $cmsQueryContainer)
    {
        $this->cmsQueryContainer = $cmsQueryContainer;
    }

    /**
     * @param int|null $idPage
     *
     * @return array
     */
    public function getData($idPage = null)
    {
        if ($idPage === null) {
            return [];
        }

        $pageUrlTemplate = $this
            ->cmsQueryContainer
            ->queryPageWithTemplatesAndUrlByIdPage($idPage)
            ->findOne();

        return [
            CmsPageForm::FIELD_ID_CMS_PAGE => $pageUrlTemplate->getIdCmsPage(),
            CmsPageForm::FIELD_FK_TEMPLATE => $pageUrlTemplate->getFkTemplate(),
            CmsPageForm::FIELD_URL => $pageUrlTemplate->getUrl(),
            CmsPageForm::FIELD_CURRENT_TEMPLATE => $pageUrlTemplate->getFkTemplate(),
            CmsPageForm::FIELD_IS_ACTIVE => $pageUrlTemplate->getIsActive(),
            CmsPageForm::FIELD_ID_URL => $pageUrlTemplate->getIdUrl(),
        ];
    }

    /**
     * @return array
     */
    public function getOptions()
    {
        return [
            CmsPageForm::OPTION_TEMPLATE_CHOICES => $this->getTemplateList(),
        ];
    }

    /**
     * @return array
     */
    protected function getTemplateList()
    {
        $templates = $this->cmsQueryContainer->queryTemplates()->find();

        $result = [];
        foreach ($templates->getData() as $template) {
            $result[$template->getIdCmsTemplate()] = $template->getTemplateName();
        }

        return $result;
    }

}