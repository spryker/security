<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockCategoryConnector\Communication\Form;

use Spryker\Zed\CmsBlockCategoryConnector\CmsBlockCategoryConnectorConfig;
use Spryker\Zed\Gui\Communication\Form\Type\ParagraphType;
use Spryker\Zed\Gui\Communication\Form\Type\Select2ComboBoxType;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class CmsBlockType extends AbstractType
{
    const FIELD_CATEGORIES = 'id_categories';

    const OPTION_CATEGORY_ARRAY = 'option-category-array';
    const OPTION_CMS_BLOCK_POSITION_LIST = 'option-cms-block-position-list';
    const OPTION_WRONG_TEMPLATE_CATEGORY_LIST = 'option-wring-template-category-list';

    /**
     * @var array
     */
    const SUPPORTED_CATEGORY_TEMPLATE_LIST = [
        CmsBlockCategoryConnectorConfig::CATEGORY_TEMPLATE_WITH_CMS_BLOCK,
        CmsBlockCategoryConnectorConfig::CATEGORY_TEMPLATE_ONLY_CMS_BLOCK,
    ];

    /**
     * @return string
     */
    public function getName()
    {
        return 'categories';
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->addWarningParagraphs(
            $builder,
            $options[static::OPTION_WRONG_TEMPLATE_CATEGORY_LIST],
            $options[static::OPTION_CATEGORY_ARRAY]
        );
        $this->addCategoryFields(
            $builder,
            $options[static::OPTION_CMS_BLOCK_POSITION_LIST],
            $options[static::OPTION_CATEGORY_ARRAY],
            $options[static::OPTION_WRONG_TEMPLATE_CATEGORY_LIST]
        );
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver
            ->setRequired(static::OPTION_CATEGORY_ARRAY)
            ->setRequired(static::OPTION_CMS_BLOCK_POSITION_LIST)
            ->setRequired(static::OPTION_WRONG_TEMPLATE_CATEGORY_LIST);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $positions
     * @param array $categoryList
     * @param array $wrongCategoryList
     *
     * @return $this
     */
    protected function addCategoryFields(FormBuilderInterface $builder, array $positions, array $categoryList, array $wrongCategoryList)
    {
        foreach ($positions as $idCmsBlockCategoryPosition => $positionName) {
            $this->addCategoryField($builder, $categoryList, $idCmsBlockCategoryPosition, $positionName);
        }

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $wrongCategoryList
     * @param array $categoryList
     *
     * @return void
     */
    protected function addWarningParagraphs(FormBuilderInterface $builder, array $wrongCategoryList, array $categoryList)
    {
        $warningCategoryList = [];
        foreach ($wrongCategoryList as $idCmsBlockCategoryPosition => $list) {
            foreach ($list as $idCategory) {
                if ($categoryList[$idCategory]) {
                    $warningCategoryList[] = $categoryList[$idCategory];
                }
            }
        }

        if (!$warningCategoryList) {
            return;
        }

        $builder->add(static::FIELD_CATEGORIES . '_paragraph', ParagraphType::class, [
            'text' => $this->formatWrongCategoryTemplateWarningMessage($warningCategoryList),
        ]);
    }

    /**
     * @param array $categoryList
     *
     * @return string
     */
    protected function formatWrongCategoryTemplateWarningMessage(array $categoryList)
    {
        $warningMessage = '<i class="fa fa-exclamation-triangle"></i> ';
        $warningMessage .= 'Please note, for categories: ';
        $warningMessage .= implode(',', $categoryList);
        $warningMessage .= ', this block will not be displayed. To display the block please change category template to one of';
        $warningMessage .= ' templates with Cms Block support.';

        return $warningMessage;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $categoryList
     * @param int $idCmsBlockCategoryPosition
     * @param string $positionName
     *
     * @return void
     */
    protected function addCategoryField(FormBuilderInterface $builder, array $categoryList, $idCmsBlockCategoryPosition, $positionName)
    {
        $builder->add(static::FIELD_CATEGORIES . '_' . $idCmsBlockCategoryPosition, Select2ComboBoxType::class, [
            'property_path' => static::FIELD_CATEGORIES . '[' . $idCmsBlockCategoryPosition . ']',
            'label' => 'Categories: ' . $positionName,
            'choices' => $categoryList,
            'multiple' => true,
            'required' => false,
        ]);
    }
}
