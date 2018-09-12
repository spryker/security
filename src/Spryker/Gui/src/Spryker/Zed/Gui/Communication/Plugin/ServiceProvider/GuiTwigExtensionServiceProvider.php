<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Gui\Communication\Plugin\ServiceProvider;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Spryker\Zed\Gui\Communication\Form\Type\Extension\NoValidateTypeExtension;
use Spryker\Zed\Gui\GuiDependencyProvider;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Twig_Environment;

/**
 * @method \Spryker\Zed\Gui\Communication\GuiCommunicationFactory getFactory()
 */
class GuiTwigExtensionServiceProvider extends AbstractPlugin implements ServiceProviderInterface
{
    /**
     * @param \Silex\Application $app
     *
     * @return void
     */
    public function register(Application $app)
    {
        $this->provideFormTypeExtension($app);

        $app['twig'] = $app->share(
            $app->extend('twig', function (Twig_Environment $twig) {

                $this->registerTwigFunctions($twig);
                $this->registerTwigFilters($twig);

                return $twig;
            })
        );
    }

    /**
     * @param \Twig_Environment $twig
     *
     * @return void
     */
    protected function registerTwigFunctions(Twig_Environment $twig)
    {
        foreach ($this->getTwigFunctions() as $function) {
            $twig->addFunction($function);
        }
    }

    /**
     * @param \Twig_Environment $twig
     *
     * @return void
     */
    protected function registerTwigFilters(Twig_Environment $twig)
    {
        foreach ($this->getTwigFilters() as $filter) {
            $twig->addFilter($filter);
        }
    }

    /**
     * @return \Twig_SimpleFunction[]
     */
    protected function getTwigFunctions()
    {
        return $this->getFactory()
            ->getProvidedDependency(GuiDependencyProvider::GUI_TWIG_FUNCTIONS);
    }

    /**
     * @return \Twig_SimpleFilter[]
     */
    protected function getTwigFilters()
    {
        return $this->getFactory()
            ->getProvidedDependency(GuiDependencyProvider::GUI_TWIG_FILTERS);
    }

    /**
     * @param \Silex\Application $app
     *
     * @return void
     */
    public function boot(Application $app)
    {
    }

    /**
     * @param \Silex\Application $app
     *
     * @return void
     */
    protected function provideFormTypeExtension(Application $app)
    {
        $app['form.type.extensions'] = $app->share(function () {
            return [
                new NoValidateTypeExtension(),
            ];
        });
    }
}
