<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyBusinessUnitGui\Communication\Plugin;

use Spryker\Zed\CompanyUserGuiExtension\Dependency\Plugin\CustomerCompanyAttachFormExpanderPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Symfony\Component\Form\FormBuilderInterface;

/**
 * @method \Spryker\Zed\CompanyBusinessUnitGui\Communication\CompanyBusinessUnitGuiCommunicationFactory getFactory()
 */
class BusinessUnitFieldCustomerCompanyAttachFormExpanderPlugin extends AbstractPlugin implements CustomerCompanyAttachFormExpanderPluginInterface
{
    /**
     * {@inheritdoc}
     *  - Expand CustomerCompanyAttachForm on choice of company business units form CompanyUserBusinessUnitChoiceFormType.
     *
     * @api
     *
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return \Symfony\Component\Form\FormBuilderInterface
     */
    public function buildForm(FormBuilderInterface $builder): FormBuilderInterface
    {
        $formType = $this->getFactory()
            ->createCompanyUserBusinessUnitChoiceFormType();

        $dataProvider = $this->getFactory()
            ->createCompanyUserBusinessUnitChoiceFormDataProvider();

        $companyUserTransfer = $builder->getData();
        $dataProvider->getData($companyUserTransfer);

        $formType->buildForm(
            $builder,
            $dataProvider->getOptions()
        );

        return $builder;
    }
}
