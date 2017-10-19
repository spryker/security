<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductLabelGui\Communication\Form;

use Generated\Shared\Transfer\ProductLabelLocalizedAttributesTransfer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class ProductLabelLocalizedAttributesFormType extends AbstractType
{
    const FIELD_LOCALE_ID = 'localeId';
    const FIELD_LOCALE_NAME = 'localeName';
    const FIELD_NAME = 'name';

    /**
     * @return string
     */
    public function getName()
    {
        return 'productLabelLocalizedAttributes';
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults([
            'data_class' => ProductLabelLocalizedAttributesTransfer::class,
        ]);
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
            ->addLocaleIdField($builder)
            ->addAttributeFields($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addLocaleIdField(FormBuilderInterface $builder)
    {
        $builder->add(
            static::FIELD_LOCALE_ID,
            HiddenType::class,
            [
                'property_path' => 'fkLocale',
            ]
        );

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addAttributeFields(FormBuilderInterface $builder)
    {
        $this->addNameField($builder);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return void
     */
    protected function addNameField(FormBuilderInterface $builder)
    {
        $builder->add(
            static::FIELD_NAME,
            TextType::class,
            [
                'label' => 'Name',
                'required' => false,
            ]
        );
    }
}
