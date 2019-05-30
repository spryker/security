<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSetGui\Communication\Form\Images;

use Spryker\Zed\Gui\Communication\Form\Type\ImageType;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\Extension\Core\Type\NumberType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\LessThanOrEqual;
use Symfony\Component\Validator\Constraints\NotBlank;

/**
 * @method \Spryker\Zed\ProductSetGui\Communication\ProductSetGuiCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductSetGui\Persistence\ProductSetGuiQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductSetGui\ProductSetGuiConfig getConfig()
 */
class ProductImageFormType extends AbstractType
{
    public const FIELD_ID_PRODUCT_IMAGE = 'id_product_image';
    public const FIELD_IMAGE_SMALL = 'external_url_small';
    public const FIELD_IMAGE_LARGE = 'external_url_large';
    public const FIELD_SORT_ORDER = 'sort_order';
    public const FIELD_IMAGE_PREVIEW = 'image_preview';
    public const FIELD_IMAGE_PREVIEW_LARGE_URL = 'image_preview_large_url';
    public const FIELD_FK_IMAGE_SET_ID = 'fk_image_set_id';

    public const OPTION_IMAGE_PREVIEW_LARGE_URL = 'option_image_preview_large_url';

    public const MAX_SORT_ORDER_VALUE = 2147483647; // 32 bit integer
    public const DEFAULT_SORT_ORDER_VALUE = 0;

    /**
     * @uses \Spryker\Zed\Gui\Communication\Form\Type\ImageType::OPTION_IMAGE_WIDTH
     */
    protected const OPTION_IMAGE_WIDTH = 'image_width';

    /**
     * @return string
     */
    public function getBlockPrefix()
    {
        return 'product_image_collection';
    }

    /**
     * @deprecated Use `getBlockPrefix()` instead.
     *
     * @return string
     */
    public function getName()
    {
        return $this->getBlockPrefix();
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
            ->addProductImageIdHiddenField($builder)
            ->addProductImageLargeUrlField($builder)
            ->addImageSetIdHiddenField($builder)
            ->addImagePreviewField($builder)
            ->addImageSmallField($builder)
            ->addImageBigField($builder)
            ->addSortOrderField($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addProductImageIdHiddenField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_ID_PRODUCT_IMAGE, HiddenType::class);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addProductImageLargeUrlField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_IMAGE_PREVIEW_LARGE_URL, ImageType::class, [
            'label' => false,
            static::OPTION_IMAGE_WIDTH => 150,
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addImageSetIdHiddenField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_FK_IMAGE_SET_ID, HiddenType::class);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addImagePreviewField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_IMAGE_PREVIEW, ImageType::class, [
            'label' => false,
            static::OPTION_IMAGE_WIDTH => 150,
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addImageSmallField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_IMAGE_SMALL, TextType::class, [
            'label' => 'Small Image URL',
            'required' => true,
            'constraints' => [
                new NotBlank(),
                new Length([
                    'min' => 0,
                    'max' => 2048,
                ]),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addImageBigField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_IMAGE_LARGE, TextType::class, [
            'label' => 'Large Image URL',
            'required' => true,
            'constraints' => [
                new NotBlank(),
                new Length([
                    'min' => 0,
                    'max' => 2048,
                ]),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addSortOrderField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_SORT_ORDER, NumberType::class, [
            'constraints' => [
                new LessThanOrEqual([
                    'value' => static::MAX_SORT_ORDER_VALUE,
                ]),
            ],
            'attr' => [
                'data-sort-order' => static::DEFAULT_SORT_ORDER_VALUE,
            ],
        ]);

        return $this;
    }
}
