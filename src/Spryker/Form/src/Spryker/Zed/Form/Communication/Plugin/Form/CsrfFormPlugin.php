<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Form\Communication\Plugin\Form;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\FormExtension\Dependency\Plugin\FormPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Symfony\Component\Form\Extension\Csrf\CsrfExtension;
use Symfony\Component\Form\FormFactoryBuilderInterface;
use Symfony\Component\Translation\TranslatorInterface;

/**
 * @method \Spryker\Zed\Form\FormConfig getConfig()
 * @method \Spryker\Zed\Form\Communication\FormCommunicationFactory getFactory()
 */
class CsrfFormPlugin extends AbstractPlugin implements FormPluginInterface
{
    public const SERVICE_CSRF_PROVIDER = 'form.csrf_provider';
    public const SERVICE_TRANSLATOR = 'translator';

    /**
     * {@inheritdoc}
     * - Adds `Symfony\Component\Form\Extension\Csrf\CsrfExtension` to `form.factory` service.
     *
     * @api
     *
     * @param \Symfony\Component\Form\FormFactoryBuilderInterface $formFactoryBuilder
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Form\FormFactoryBuilderInterface
     */
    public function extend(FormFactoryBuilderInterface $formFactoryBuilder, ContainerInterface $container): FormFactoryBuilderInterface
    {
        $formFactoryBuilder->addExtension(
            $this->createCsrfExtension($container)
        );

        return $formFactoryBuilder;
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Form\Extension\Csrf\CsrfExtension
     */
    protected function createCsrfExtension(ContainerInterface $container): CsrfExtension
    {
        return new CsrfExtension(
            $container->get(static::SERVICE_CSRF_PROVIDER),
            $this->getTranslator($container)
        );
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Translation\TranslatorInterface|null
     */
    protected function getTranslator(ContainerInterface $container): ?TranslatorInterface
    {
        return $container->has(static::SERVICE_TRANSLATOR) ? $container->get(static::SERVICE_TRANSLATOR) : null;
    }
}
