<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Form\Voucher;

use Generated\Shared\Transfer\ManualOrderTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * @method \Spryker\Zed\ManualOrderEntryGui\Communication\ManualOrderEntryGuiCommunicationFactory getFactory()
 * @method \Spryker\Zed\ManualOrderEntryGui\ManualOrderEntryGuiConfig getConfig()
 */
class VoucherType extends AbstractType
{
    public const TYPE_NAME = 'voucher';

    public const FIELD_VOUCHER_CODE = 'voucherCode';

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver): void
    {
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $this
            ->addVoucherCodeField($builder, $options);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    protected function addVoucherCodeField(FormBuilderInterface $builder, array $options): self
    {
        $builder->add(static::FIELD_VOUCHER_CODE, TextType::class, [
            'property_path' => QuoteTransfer::MANUAL_ORDER . '.' . ManualOrderTransfer::VOUCHER_CODE,
            'label' => 'Add Voucher',
            'required' => false,
        ]);

        return $this;
    }

    /**
     * @return string
     */
    public function getBlockPrefix(): string
    {
        return static::TYPE_NAME;
    }
}
