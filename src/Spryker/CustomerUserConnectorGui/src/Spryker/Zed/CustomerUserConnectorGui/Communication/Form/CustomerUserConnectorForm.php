<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerUserConnectorGui\Communication\Form;

use Generated\Shared\Transfer\CustomerUserConnectionUpdateTransfer;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\CallbackTransformer;
use Symfony\Component\Form\Extension\Core\Type\HiddenType;
use Symfony\Component\Form\FormBuilderInterface;

class CustomerUserConnectorForm extends AbstractType
{

    const FIELD_ID_USER = CustomerUserConnectionUpdateTransfer::ID_USER;
    const FIELD_IDS_CUSTOMER_TO_ASSIGN_CSV = CustomerUserConnectionUpdateTransfer::ID_CUSTOMERS_TO_ASSIGN;
    const FIELD_IDS_CUSTOMER_TO_DE_ASSIGN_CSV = CustomerUserConnectionUpdateTransfer::ID_CUSTOMERS_TO_DE_ASSIGN;

    /**
     * @return string
     */
    public function getName()
    {
        return 'customerUserConnection';
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
            ->addIdUserField($builder)
            ->addIdsCustomerToAssignCsvField($builder)
            ->addIdsCustomerToDeAssignCsvField($builder);
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdUserField(FormBuilderInterface $builder)
    {
        $builder->add(
            static::FIELD_ID_USER,
            HiddenType::class
        );

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdsCustomerToAssignCsvField(FormBuilderInterface $builder)
    {
        $builder->add(
            static::FIELD_IDS_CUSTOMER_TO_ASSIGN_CSV,
            HiddenType::class
        );

        $this->addIdsCsvModelTransformer(static::FIELD_IDS_CUSTOMER_TO_ASSIGN_CSV, $builder);

        return $this;
    }

    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return $this
     */
    protected function addIdsCustomerToDeAssignCsvField(FormBuilderInterface $builder)
    {
        $builder->add(
            static::FIELD_IDS_CUSTOMER_TO_DE_ASSIGN_CSV,
            HiddenType::class
        );

        $this->addIdsCsvModelTransformer(static::FIELD_IDS_CUSTOMER_TO_DE_ASSIGN_CSV, $builder);

        return $this;
    }

    /**
     * @param string $fieldName
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return void
     */
    protected function addIdsCsvModelTransformer($fieldName, FormBuilderInterface $builder)
    {
        $builder
            ->get($fieldName)
            ->addModelTransformer(new CallbackTransformer(
                function ($idsCustomerAsArray) {
                    if (!count($idsCustomerAsArray)) {
                        return [];
                    }

                    return implode(',', $idsCustomerAsArray);
                },
                function ($idsCustomerAsCsv) {
                    if (empty($idsCustomerAsCsv)) {
                        return [];
                    }

                    return explode(',', $idsCustomerAsCsv);
                }
            ));
    }

}
