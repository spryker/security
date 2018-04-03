<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Chart\Plugin\Twig;

class TwigChartPlugin extends AbstractTwigChartPlugin
{
    const TWIG_FUNCTION_NAME = 'spyChart';

    /**
     * @return string
     */
    protected function getTemplateName(): string
    {
        return '@Chart/_template/chart.twig';
    }
}
