<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Mail\Dependency\Renderer;

use Generated\Shared\Transfer\LocaleTransfer;

class MailToRendererBridge implements MailToRendererInterface
{
    /**
     * @var \Twig_Environment
     */
    protected $twigEnvironment;

    /**
     * @param \Twig_Environment $twigEnvironment
     */
    public function __construct($twigEnvironment)
    {
        $this->twigEnvironment = $twigEnvironment;
    }

    /**
     * @param string $template
     * @param array $options
     *
     * @return string
     */
    public function render($template, array $options)
    {
        return $this->twigEnvironment->render($template, $options);
    }

    /**
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @return void
     */
    public function setLocaleTransfer(LocaleTransfer $localeTransfer)
    {
        $translator = $this->getTranslator();
        $translator->setLocaleTransfer($localeTransfer);
    }

    /**
     * @return \Twig_ExtensionInterface|\Spryker\Zed\Glossary\Communication\Plugin\TwigTranslatorPlugin
     */
    protected function getTranslator()
    {
        $translator = $this->twigEnvironment->getExtension('translator');

        return $translator;
    }
}
