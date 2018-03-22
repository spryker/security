<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Gui\Communication\Plugin\Twig;

use Generated\Shared\Transfer\TabsViewTransfer;
use Spryker\Shared\Twig\TwigFunction;
use Twig_Environment;

class TabsFunction extends TwigFunction
{
    /**
     * @return string
     */
    protected function getFunctionName()
    {
        return 'tabs';
    }

    /**
     * @return callable
     */
    protected function getFunction()
    {
        return [$this, 'tabs'];
    }

    /**
     * @return array
     */
    public function getOptions()
    {
        $options = parent::getOptions();

        $options['needs_environment'] = true;

        return $options;
    }

    /**
     * @param \Twig_Environment $twig
     * @param \Generated\Shared\Transfer\TabsViewTransfer $tabsViewTransfer
     * @param array $context
     *
     * @return string
     */
    public function tabs(Twig_Environment $twig, TabsViewTransfer $tabsViewTransfer, array $context = [])
    {
        $context['tabsViewTransfer'] = $tabsViewTransfer;

        return $twig->render('@Gui/Tabs/tabs.twig', $context);
    }
}
