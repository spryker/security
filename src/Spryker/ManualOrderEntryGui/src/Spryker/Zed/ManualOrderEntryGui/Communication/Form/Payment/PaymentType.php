<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Form\Payment;

use Generated\Shared\Transfer\PaymentTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\Kernel\Communication\Form\AbstractType;
use Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface;
use Symfony\Component\Form\Extension\Core\Type\ChoiceType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\Constraints\NotBlank;

/**
 * @method \Spryker\Zed\ManualOrderEntryGui\Communication\ManualOrderEntryGuiCommunicationFactory getFactory()
 */
class PaymentType extends AbstractType
{

    const PAYMENT_PROPERTY_PATH = QuoteTransfer::PAYMENT;
    const PAYMENT_SELECTION = PaymentTransfer::PAYMENT_SELECTION;
    const PAYMENT_SELECTION_PROPERTY_PATH = self::PAYMENT_PROPERTY_PATH . '.' . self::PAYMENT_SELECTION;

    const KEY_SUBFORM = 'SUBFORM';
    const KEY_PLUGIN = 'PLUGIN';

    const OPTIONS_FIELD_NAME = 'select_options';

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return void
     *
     * @throws \Spryker\Zed\Kernel\Exception\Container\ContainerKeyNotFoundException
     */
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $this->addPaymentMethods($builder, $options);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $options
     *
     * @return $this
     *
     * @throws \Spryker\Zed\Kernel\Exception\Container\ContainerKeyNotFoundException
     */
    protected function addPaymentMethods(FormBuilderInterface $builder, array $options)
    {
        $paymentSubFormPlugins = $this->getFactory()
            ->getPaymentMethodSubFormPluginCollection();
        $paymentMethodSubForms = $this->getPaymentMethodSubForms($paymentSubFormPlugins);
        $paymentMethodChoices = $this->getPaymentMethodChoices($paymentMethodSubForms);

        $this->addPaymentMethodChoices($builder, $paymentMethodChoices)
            ->addPaymentMethodSubForms($builder, $paymentMethodSubForms, $options);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $paymentMethodChoices
     *
     * @return $this
     */
    protected function addPaymentMethodChoices(FormBuilderInterface $builder, array $paymentMethodChoices)
    {
        $builder->add(
            static::PAYMENT_SELECTION,
            ChoiceType::class,
            [
                'choices' => $paymentMethodChoices,
                'label' => false,
                'required' => true,
                'expanded' => true,
                'multiple' => false,
                'placeholder' => false,
                'property_path' => self::PAYMENT_SELECTION_PROPERTY_PATH,
                'constraints' => [
                    new NotBlank(),
                ],
            ]
        );

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     * @param array $paymentMethodSubForms
     * @param array $options
     *
     * @return $this
     */
    protected function addPaymentMethodSubForms(FormBuilderInterface $builder, array $paymentMethodSubForms, array $options)
    {
        foreach ($paymentMethodSubForms as $paymentMethodSubForm) {
            $builder->add(
                $paymentMethodSubForm[static::KEY_PLUGIN]->getName(),
                get_class($paymentMethodSubForm[static::KEY_SUBFORM]),
                [
                    'property_path' => static::PAYMENT_PROPERTY_PATH . '.' . $paymentMethodSubForm[static::KEY_PLUGIN]->getPropertyPath(),
                    'error_bubbling' => true,
                    static::OPTIONS_FIELD_NAME => $options[static::OPTIONS_FIELD_NAME],
                ]
            );
        }

        return $this;
    }

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginCollection $paymentSubFormPlugins
     *
     * @return array
     */
    protected function getPaymentMethodSubForms($paymentSubFormPlugins)
    {
        $paymentMethodSubForms = [];

        foreach ($paymentSubFormPlugins as $paymentMethodSubFormPlugin) {
            $subform = $this->createSubForm($paymentMethodSubFormPlugin);

            $paymentMethodSubForms[] = [
                static::KEY_PLUGIN => $paymentMethodSubFormPlugin,
                static::KEY_SUBFORM => $subform,
            ];
        }

        return $paymentMethodSubForms;
    }

    /**
     * @param array $paymentMethodSubForms
     *
     * @return array
     */
    protected function getPaymentMethodChoices(array $paymentMethodSubForms)
    {
        $choices = [];

        foreach ($paymentMethodSubForms as $paymentMethodSubForm) {
            $subFormName = ucfirst($paymentMethodSubForm[static::KEY_PLUGIN]->getName());

            $choices[$subFormName] = $paymentMethodSubForm[static::KEY_PLUGIN]->getPropertyPath();
        }

        return $choices;
    }

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Communication\Plugin\Payment\SubFormPluginInterface $paymentMethodSubForm
     *
     * @return \Spryker\Zed\Kernel\Communication\Form\AbstractType
     */
    protected function createSubForm(SubFormPluginInterface $paymentMethodSubForm)
    {
        return $paymentMethodSubForm->createSubForm();
    }

    /**
     * @param \Symfony\Component\OptionsResolver\OptionsResolver $resolver
     *
     * @return void
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults([
            'validation_groups' => function (FormInterface $form) {
                return [
                    Constraint::DEFAULT_GROUP,
                    $form->get(static::PAYMENT_SELECTION)->getData(),
                ];
            },
            'attr' => [
                'novalidate' => 'novalidate',
            ],
        ]);

        $resolver->setRequired(static::OPTIONS_FIELD_NAME);
    }

    /**
     * @return string
     */
    public function getBlockPrefix()
    {
        return 'payments';
    }

}
