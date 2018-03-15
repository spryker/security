<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Form\Product;

use ArrayObject;
use Generated\Shared\Transfer\QuoteTransfer;
use Symfony\Component\Form\CallbackTransformer;
use Symfony\Component\Form\Extension\Core\Type\CollectionType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvent;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;

/**
 * @method \Spryker\Zed\ManualOrderEntryGui\Communication\ManualOrderEntryGuiCommunicationFactory getFactory()
 */
class ProductCollectionType extends AbstractType
{

    const FIELD_PRODUCTS = 'manualOrderProducts';
    const FIELD_IS_PRODUCT_POSTED = 'isProductPosted';

    const OPTION_MANUAL_ORDER_PRODUCT_CLASS_COLLECTION = 'manual_order_product_class_collection';

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setRequired(static::OPTION_MANUAL_ORDER_PRODUCT_CLASS_COLLECTION);
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
            ->addProductsEmptyField($builder, $options)
            ->addIsProductPostedField($builder, $options)
        ;

    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    protected function addProductsEmptyField(FormBuilderInterface $builder, array $options)
    {
        $builder->add(self::FIELD_PRODUCTS, CollectionType::class, [
            'entry_type' => ProductType::class,
            'label' => 'Products',
            'required' => false,
            'allow_add' => true,
            'allow_delete' => true,
            'entry_options' => [
                'data_class' => $options[static::OPTION_MANUAL_ORDER_PRODUCT_CLASS_COLLECTION],
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    protected function addIsProductPostedField(FormBuilderInterface $builder, array $options)
    {
        $builder->add(self::FIELD_IS_PRODUCT_POSTED, HiddenType::class, [
            'data' => 1,
        ]);

        return $this;
    }

    /**
     * @return string
     */
    public function getBlockPrefix()
    {
        return 'products';
    }

}
