<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationship\Communication\Form;

use Generated\Shared\Transfer\PriceProductDimensionTransfer;
use Spryker\Shared\PriceProductMerchantRelationship\PriceProductMerchantRelationshipConfig;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;

class MerchantPriceDimensionForm extends AbstractType
{
    public const OPTION_VALUES_MERCHANT_RELATIONSHIP_CHOICES = 'merchant_relationship_choices';

    public const FIELD_PLACEHOLDER_MERCHANT_RELATIONSHIP = 'Default prices';
    public const FIELD_LABEL_MERCHANT_RELATIONSHIP = 'Merchant Price Dimension';

    protected const TEMPLATE_PATH = '@PriceProductMerchantRelationship/ProductManagement/price_dimension.twig';

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $this->addMerchantRelationshipCollectionField($builder, $options);
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver): void
    {
        parent::configureOptions($resolver);

        $resolver->setRequired(static::OPTION_VALUES_MERCHANT_RELATIONSHIP_CHOICES);
        $resolver->setDefaults([
            'label' => false,
            'mapped' => false,
        ]);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     */
    protected function addMerchantRelationshipCollectionField(FormBuilderInterface $builder, array $options): self
    {
        $builder->add(PriceProductDimensionTransfer::ID_MERCHANT_RELATIONSHIP, ChoiceType::class, [
            'choices' => $options[static::OPTION_VALUES_MERCHANT_RELATIONSHIP_CHOICES],
            'placeholder' => static::FIELD_PLACEHOLDER_MERCHANT_RELATIONSHIP,
            'choices_as_values' => true,
            'label' => static::FIELD_LABEL_MERCHANT_RELATIONSHIP,
            'attr' => [
                'template_path' => $this->getTemplatePath(),
                'data-type' => PriceProductMerchantRelationshipConfig::PRICE_DIMENSION_MERCHANT_RELATIONSHIP,
            ],
        ]);

        return $this;
    }

    /**
     * @return string
     */
    protected function getTemplatePath(): string
    {
        return static::TEMPLATE_PATH;
    }
}
