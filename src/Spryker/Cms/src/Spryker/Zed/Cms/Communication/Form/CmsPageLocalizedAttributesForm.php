<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Cms\Communication\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Required;

class CmsPageLocalizedAttributesForm extends AbstractType
{
    const FIELD_ID_CMS_PAGE_LOCALIZED_ATTRIBUTES = 'id_cms_page_localized_attributes';
    const FIELD_FK_CMS_PAGE = 'fk_cms_page';
    const FIELD_NAME = 'name';
    const FIELD_META_TITLE = 'meta_title';
    const FIELD_META_KEYWORDS = 'meta_keywords';
    const FIELD_META_DESCRIPTION = 'meta_description';

    /**
     * @return string
     */
    public function getName()
    {
        return 'localized_attributes';
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this
            ->addIdCmsPageLocalizedAttributesField($builder)
            ->addFkCmsPageField($builder)
            ->addNameField($builder)
            ->addMetaTitleField($builder)
            ->addMetaKeywordsField($builder)
            ->addMetaDescriptionField($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdCmsPageLocalizedAttributesField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_ID_CMS_PAGE_LOCALIZED_ATTRIBUTES, HiddenType::class);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFkCmsPageField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_FK_CMS_PAGE, HiddenType::class);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addNameField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_NAME, TextType::class, [
            'label' => 'Name',
            'constraints' => [
                new Required(),
                new NotBlank(),
                new Length(['max' => 255]),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addMetaTitleField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_META_TITLE, TextType::class, [
            'label' => 'Meta title',
            'required' => false,
            'constraints' => [
                new Length(['max' => 255]),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addMetaKeywordsField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_META_KEYWORDS, TextType::class, [
            'label' => 'Meta keywords',
            'required' => false,
            'constraints' => [
                new Length(['max' => 255]),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addMetaDescriptionField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_META_DESCRIPTION, TextType::class, [
            'label' => 'Meta description',
            'required' => false,
            'constraints' => [
                new Length(['max' => 255]),
            ],
        ]);

        return $this;
    }
}
