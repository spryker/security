<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Security\Communication\Plugin\Validator;

use Spryker\Service\Container\ContainerInterface;
use Spryker\Shared\ValidatorExtension\Dependency\Plugin\ConstraintPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface;
use Symfony\Component\Security\Core\Validator\Constraints\UserPasswordValidator;
use Symfony\Component\Validator\ConstraintValidatorInterface;

/**
 * @method \Spryker\Zed\Security\Business\SecurityFacadeInterface getFacade()
 * @method \Spryker\Zed\Security\Communication\SecurityCommunicationFactory getFactory()
 * @method \Spryker\Zed\Security\SecurityConfig getConfig()
 */
class UserPasswordValidatorConstraintPlugin extends AbstractPlugin implements ConstraintPluginInterface
{
    /**
     * @var string
     */
    protected const CONSTRAINT_NAME = 'security.validator.user_password';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_TOKEN_STORAGE = 'security.token_storage';

    /**
     * @var string
     */
    protected const SERVICE_SECURITY_ENCODER_FACTORY = 'security.encoder_factory';

    /**
     * {@inheritDoc}
     *
     * @api
     *
     * @return string
     */
    public function getName(): string
    {
        return static::CONSTRAINT_NAME;
    }

    /**
     * {@inheritDoc}
     * - Returns an instance of `Symfony\Component\Security\Core\Validator\Constraints\UserPasswordValidator` constraint.
     *
     * @api
     *
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Validator\ConstraintValidatorInterface
     */
    public function getConstraintInstance(ContainerInterface $container): ConstraintValidatorInterface
    {
        return $this->createUserPasswordValidator($container);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Validator\ConstraintValidatorInterface
     */
    protected function createUserPasswordValidator(ContainerInterface $container): ConstraintValidatorInterface
    {
        return new UserPasswordValidator($this->getTokenStorage($container), $this->getEncoderStorage($container));
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
     */
    protected function getTokenStorage(ContainerInterface $container): TokenStorageInterface
    {
        return $container->get(static::SERVICE_SECURITY_TOKEN_STORAGE);
    }

    /**
     * @param \Spryker\Service\Container\ContainerInterface $container
     *
     * @return \Symfony\Component\Security\Core\Encoder\EncoderFactoryInterface
     */
    protected function getEncoderStorage(ContainerInterface $container): EncoderFactoryInterface
    {
        return $container->get(static::SERVICE_SECURITY_ENCODER_FACTORY);
    }
}
