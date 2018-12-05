<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CategoryImageGui\Communication\Form;

use Spryker\Zed\CategoryExtension\Dependency\Plugin\CategoryFormPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Symfony\Component\Form\FormBuilderInterface;

/**
 * @method \Spryker\Zed\CategoryImageGui\Communication\CategoryImageGuiCommunicationFactory getFactory()
 */
class CategoryImageFormPlugin extends AbstractPlugin implements CategoryFormPluginInterface
{
    public const FIELD_IMAGE_SETS = 'imageSets';

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Symfony\Component\Form\FormBuilderInterface $builder
     *
     * @return void
     */
    public function buildForm(FormBuilderInterface $builder)
    {
        $localeFacade = $this->getFactory()->getLocaleFacade();
        $builder->add(static::FIELD_IMAGE_SETS, ImageSetCollectionForm::class, [
            ImageSetCollectionForm::OPTION_LOCALES => $localeFacade->getAvailableLocales(),
        ]);
        $builder->get(static::FIELD_IMAGE_SETS)->addModelTransformer(
            $this->getFactory()->createImageSetCollectionTransformer()
        );
    }
}
