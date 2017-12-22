<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductLabelGui\Communication\Form;

use Generated\Shared\Transfer\ProductLabelAggregateFormTransfer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormTypeInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class ProductLabelAggregateFormType extends AbstractType
{
    /**
     * @var \Spryker\Zed\ProductLabelGui\Communication\Form\ProductLabelFormType|\Symfony\Component\Form\FormTypeInterface
     */
    protected $productLabelFormType;

    /**
     * @var \Spryker\Zed\ProductLabelGui\Communication\Form\RelatedProductFormType|\Symfony\Component\Form\FormTypeInterface
     */
    protected $relatedProductFormType;

    /**
     * @param \Symfony\Component\Form\FormTypeInterface $productLabelFormType
     * @param \Symfony\Component\Form\FormTypeInterface $relatedProductFormType
     */
    public function __construct(
        FormTypeInterface $productLabelFormType,
        FormTypeInterface $relatedProductFormType
    ) {
        $this->productLabelFormType = $productLabelFormType;
        $this->relatedProductFormType = $relatedProductFormType;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return 'productLabelAggregate';
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
            'data_class' => ProductLabelAggregateFormTransfer::class,
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
            ->addProductLabelSubForm($builder)
            ->addRelatedProductSubForm($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addProductLabelSubForm(FormBuilderInterface $builder)
    {
        $builder->add(
            ProductLabelAggregateFormTransfer::PRODUCT_LABEL,
            $this->productLabelFormType,
            [
                'label' => false,
            ]
        );

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addRelatedProductSubForm(FormBuilderInterface $builder)
    {
        $builder->add(
            ProductLabelAggregateFormTransfer::PRODUCT_ABSTRACT_RELATIONS,
            $this->relatedProductFormType,
            [
                'label' => false,
            ]
        );

        return $this;
    }
}
