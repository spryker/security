<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesSplit\Communication\Form;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;

class OrderItemSplitForm extends AbstractType
{
    const FIELD_QUANTITY = 'quantity';
    const FIELD_ID_ORDER_ITEM = 'id_sales_order_item';
    const FIELD_ID_ORDER = 'id_sales_order';

    const VALIDATE_MESSAGE_NUMERIC = 'Please provide numeric value.';
    const VALIDATION_MESSAGE_QUANTITY = 'Please provide quantity.';

    /**
     * @return string
     */
    public function getName()
    {
        return 'orderItemSplit';
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder->setAction('/sales-split/order-item-split/split');

        $this
            ->addQuantityField($builder)
            ->addIdOrderItemField($builder)
            ->addIdOrderField($builder)
            ->addSubmitButton($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addQuantityField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_QUANTITY, 'text', [
            'label' => 'Quantity',
            'constraints' => [
                new NotBlank([
                    'message' => self::VALIDATION_MESSAGE_QUANTITY,
                ]),
                new Regex([
                    'pattern' => '/^\d+$/',
                    'message' => self::VALIDATE_MESSAGE_NUMERIC,
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
    protected function addIdOrderItemField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_ID_ORDER_ITEM, 'hidden');

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdOrderField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_ID_ORDER, 'hidden');

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addSubmitButton(FormBuilderInterface $builder)
    {
        $builder->add('Split', 'submit', [
            'attr' => [
                'class' => 'btn btn-sm btn-primary',
            ],
        ]);

        return $this;
    }
}
