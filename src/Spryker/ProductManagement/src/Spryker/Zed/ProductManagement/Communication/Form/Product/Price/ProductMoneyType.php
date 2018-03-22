<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductManagement\Communication\Form\Product\Price;

use Generated\Shared\Transfer\MoneyValueTransfer;
use Generated\Shared\Transfer\PriceProductTransfer;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\Form\FormView;

/**
 * @method \Spryker\Zed\ProductManagement\Communication\ProductManagementCommunicationFactory getFactory()
 */
class ProductMoneyType extends AbstractType
{
    const FIELD_FK_PRICE_TYPE = 'fk_price_type';

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param string[] $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->addFieldFkPriceType($builder);

        $builder->add(
            PriceProductTransfer::MONEY_VALUE,
            $this->getFactory()->getMoneyFormTypePlugin()->getType(),
            [
                'data_class' => MoneyValueTransfer::class,
            ]
        );
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFieldFkPriceType(FormBuilderInterface $builder)
    {
        $builder->add(static::FIELD_FK_PRICE_TYPE, HiddenType::class);

        return $this;
    }

    /**
     * {@inheritdoc}
     *
     */
    public function buildView(FormView $view, FormInterface $form, array $options)
    {
        $viewData = $form->getViewData();
        $view->vars['price_type'] = $viewData->getPriceType();
    }
}
