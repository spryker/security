<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SprykGui\Business\ChoiceLoader\Client;

use Generated\Shared\Transfer\ModuleTransfer;
use ReflectionMethod;
use Spryker\Zed\SprykGui\Business\ChoiceLoader\Common\AbstractMethodChoiceLoader;

class ClientMethodChoiceLoader extends AbstractMethodChoiceLoader
{
    /**
     * @param \Generated\Shared\Transfer\ModuleTransfer $moduleTransfer
     *
     * @return string
     */
    protected function getClassName(ModuleTransfer $moduleTransfer): string
    {
        $dependentModule = $moduleTransfer->getDependentModule();

        return sprintf('\\Spryker\\Client\\%1$s\\%1$sClient', $dependentModule->getName());
    }

    /**
     * @param \ReflectionMethod $reflectionMethod
     *
     * @return bool
     */
    protected function acceptMethod(ReflectionMethod $reflectionMethod): bool
    {
        return $reflectionMethod->isPublic();
    }

    /**
     * @param \Generated\Shared\Transfer\ModuleTransfer $moduleTransfer
     * @param \ReflectionMethod $reflectionMethod
     *
     * @return string
     */
    protected function buildChoiceLabel(ModuleTransfer $moduleTransfer, ReflectionMethod $reflectionMethod): string
    {
        return sprintf('%sClient::%s()', $moduleTransfer->getDependentModule()->getName(), $reflectionMethod->getName());
    }
}
