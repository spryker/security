<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Service\UtilValidate;

use Spryker\Service\Kernel\AbstractServiceFactory;

class UtilValidateServiceFactory extends AbstractServiceFactory
{
    /**
     * @return \Spryker\Service\UtilValidate\Dependency\External\UtilValidateToEmailValidatorInterface
     */
    public function getEmailValidator()
    {
        return $this->getProvidedDependency(UtilValidateDependencyProvider::EMAIL_VALIDATOR);
    }
}
