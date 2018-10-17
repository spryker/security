<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductVolumeGui\Communication\Form;

use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Spryker\Zed\PriceProductVolumeGui\Communication\Form\DataProvider\PriceVolumeCollectionDataProvider;
use Symfony\Component\Form\Extension\Core\Type\MoneyType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\GreaterThanOrEqual;
use Symfony\Component\Validator\Constraints\Regex;
use Symfony\Component\Validator\Constraints\Required;

/**
 * @method \Spryker\Zed\PriceProductVolumeGui\Business\PriceProductVolumeGuiFacadeInterface getFacade()
 * @method \Spryker\Zed\PriceProductVolumeGui\Communication\PriceProductVolumeGuiCommunicationFactory getFactory()
 */
class PriceVolumeFormType extends AbstractType
{
    public const FIELD_QUANTITY = 'quantity';
    protected const FIELD_NET_PRICE = 'net_price';
    protected const FIELD_GROSS_PRICE = 'gross_price';
    protected const MINIMUM_QUANTITY = 2;
    protected const MESSAGE_QUANTITY_ERROR = 'The quantity you have entered is invalid.';

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $this
            ->addQuantityField($builder)
            ->addGrossPriceField($builder, $options)
            ->addNetPriceField($builder, $options);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addQuantityField(FormBuilderInterface $builder): self
    {
        $builder->add(static::FIELD_QUANTITY, TextType::class, [
            'label' => 'Quantity',
            'required' => false,
            'constraints' => [
                new Required(),
                new GreaterThanOrEqual(['value' => static::MINIMUM_QUANTITY, 'message' => static::MESSAGE_QUANTITY_ERROR]),
                new Regex(['pattern' => '/[\d]+/', 'message' => static::MESSAGE_QUANTITY_ERROR]),
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
    protected function addNetPriceField(FormBuilderInterface $builder, array $options): self
    {
        $this->addPriceField($builder, $options, static::FIELD_NET_PRICE, 'Net Price');

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    protected function addGrossPriceField(FormBuilderInterface $builder, array $options): self
    {
        $this->addPriceField($builder, $options, static::FIELD_GROSS_PRICE, 'Gross Price');

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     * @param string $name
     * @param string $label
     *
     * @return $this
     */
    protected function addPriceField(FormBuilderInterface $builder, array $options, string $name, string $label): self
    {
        $builder->add($name, MoneyType::class, [
            'label' => $label,
            'currency' => $options[PriceVolumeCollectionDataProvider::OPTION_CURRENCY_CODE],
            'required' => false,
            'constraints' => [
                new GreaterThanOrEqual(0),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setRequired(PriceVolumeCollectionDataProvider::OPTION_CURRENCY_CODE);
    }
}
