<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\AvailabilityGui\Communication\Form;

use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Constraints\Required;

/**
 * @method \Spryker\Zed\AvailabilityGui\Communication\AvailabilityGuiCommunicationFactory getFactory()
 */
class StockSubForm extends AbstractType
{
    const FIELD_QUANTITY = 'quantity';
    const FIELD_STOCK_TYPE = 'stockType';
    const FIELD_IS_NEVER_OUT_OF_STOCK = 'is_never_out_of_stock';

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->addQuantityField($builder)
            ->addStockTypeField($builder)
            ->addIsNeverOutOfStockCheckbox($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addQuantityField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_QUANTITY, TextType::class, [
            'label' => 'Quantity',
            'constraints' => [
                new Required(),
                new Regex(['pattern' => '/[\d]+/']),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addStockTypeField(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_STOCK_TYPE, TextType::class, [
            'label' => 'Stock Type',
            'disabled' => true,
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIsNeverOutOfStockCheckbox(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_IS_NEVER_OUT_OF_STOCK, CheckboxType::class, [
            'label' => 'Never out of stock',
            'required' => false,
        ]);

        return $this;
    }
}
