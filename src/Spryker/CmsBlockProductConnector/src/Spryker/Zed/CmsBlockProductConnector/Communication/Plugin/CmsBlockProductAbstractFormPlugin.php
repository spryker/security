<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsBlockProductConnector\Communication\Plugin;

use Spryker\Zed\CmsBlockGui\Communication\Plugin\CmsBlockFormPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Symfony\Component\Form\FormBuilderInterface;

/**
 * @method \Spryker\Zed\CmsBlockProductConnector\Communication\CmsBlockProductConnectorCommunicationFactory getFactory()
 * @method \Spryker\Zed\CmsBlockProductConnector\Business\CmsBlockProductConnectorFacade getFacade()
 */
class CmsBlockProductAbstractFormPlugin extends AbstractPlugin implements CmsBlockFormPluginInterface
{
    /**
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder)
    {
        $formType = $this->getFactory()
            ->createCmsBlockProductAbstractType();

        $dataProvider = $this->getFactory()
            ->createCmsBlockProductDataProvider();

        $cmsBlockTransfer = $builder->getData();
        $dataProvider->getData($cmsBlockTransfer);

        $formType->buildForm(
            $builder,
            $dataProvider->getOptions()
        );
    }
}
