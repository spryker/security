<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOption\Communication\Form;

use Generated\Shared\Transfer\ProductOptionValueTransfer;
use Spryker\Zed\Kernel\Communication\Form\FormTypeInterface;
use Spryker\Zed\ProductOption\Communication\Form\Constraint\UniqueOptionValueSku;
use Spryker\Zed\ProductOption\Communication\Form\Constraint\UniqueValue;
use Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface;
use Spryker\Zed\ProductOption\ProductOptionConfig;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\DataTransformerInterface;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints\NotBlank;
use Symfony\Component\Validator\Constraints\Regex;

class ProductOptionValueForm extends AbstractType
{
    const FIELD_VALUE = 'value';
    const FIELD_SKU = 'sku';
    const FIELD_PRICES = 'prices';
    const FIELD_ID_PRODUCT_OPTION_VALUE = 'idProductOptionValue';
    const FIELD_OPTION_HASH = 'optionHash';

    const OPTION_AMOUNT_PER_STORE = 'amount_per_store';

    const ALPHA_NUMERIC_PATTERN = '/^[a-z0-9\.\_]+$/';

    /**
     * @var \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface
     */
    protected $productOptionQueryContainer;

    /**
     * @var \Symfony\Component\Form\DataTransformerInterface
     */
    protected $priceTransformer;

    /**
     * @var \Spryker\Zed\Kernel\Communication\Form\FormTypeInterface
     */
    protected $moneyCollectionFormTypePlugin;

    /**
     * @param \Spryker\Zed\Kernel\Communication\Form\FormTypeInterface $moneyCollectionFormTypePlugin
     * @param \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface $productOptionQueryContainer
     * @param \Symfony\Component\Form\DataTransformerInterface $priceTransformer
     */
    public function __construct(
        FormTypeInterface $moneyCollectionFormTypePlugin,
        ProductOptionQueryContainerInterface $productOptionQueryContainer,
        DataTransformerInterface $priceTransformer
    ) {
        $this->moneyCollectionFormTypePlugin = $moneyCollectionFormTypePlugin;
        $this->productOptionQueryContainer = $productOptionQueryContainer;
        $this->priceTransformer = $priceTransformer;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param string[] $options
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->addNameField($builder)
            ->addSkuField($builder)
            ->addPricesField($builder)
            ->addIdProductOptionValue($builder)
            ->addFormHash($builder);
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            'data_class' => ProductOptionValueTransfer::class,
            'constraints' => [
                new UniqueValue([
                    UniqueValue::OPTION_PRODUCT_OPTION_QUERY_CONTAINER => $this->productOptionQueryContainer,
                ]),
                new UniqueOptionValueSku([
                    UniqueOptionValueSku::OPTION_PRODUCT_OPTION_QUERY_CONTAINER => $this->productOptionQueryContainer,
                ]),
            ],
        ]);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addNameField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_VALUE, 'text', [
            'label' => 'Option name translation key',
            'required' => true,
            'attr' => [
                'placeholder' => ProductOptionConfig::PRODUCT_OPTION_TRANSLATION_PREFIX . '(your key)',
            ],
            'constraints' => [
                new NotBlank(),
                new Regex([
                    'pattern' => self::ALPHA_NUMERIC_PATTERN,
                    'message' => 'Invalid key provided. Valid values "a-z", "0-9", ".", "_".',
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
    protected function addSkuField(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_SKU, 'text', [
            'label' => 'Sku',
            'required' => true,
            'constraints' => [
                new NotBlank(),
            ],
        ]);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addPricesField(FormBuilderInterface $builder)
    {
        $builder->add(
            static::FIELD_PRICES,
            $this->moneyCollectionFormTypePlugin->getType(),
            [
                    static::OPTION_AMOUNT_PER_STORE => true,
            ]
        );

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdProductOptionValue(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_ID_PRODUCT_OPTION_VALUE, 'hidden');

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addFormHash(FormBuilderInterface $builder)
    {
        $builder->add(self::FIELD_OPTION_HASH, 'hidden');

        return $this;
    }

    /**
     * Returns the name of this type.
     *
     * @return string The name of this type
     */
    public function getName()
    {
        return 'product_option';
    }
}
