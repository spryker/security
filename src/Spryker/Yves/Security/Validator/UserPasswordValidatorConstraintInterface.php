<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Security\Validator;

use Spryker\Service\Container\ContainerInterface;
use Symfony\Component\Validator\ConstraintValidatorInterface;

interface UserPasswordValidatorConstraintInterface
{
    public function getConstraintInstance(ContainerInterface $container): ConstraintValidatorInterface;
}
