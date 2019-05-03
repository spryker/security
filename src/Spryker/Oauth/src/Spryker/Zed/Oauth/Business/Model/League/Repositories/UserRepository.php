<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Oauth\Business\Model\League\Repositories;

use Generated\Shared\Transfer\OauthUserTransfer;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use Spryker\Zed\Oauth\Business\Model\League\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    /**
     * @var \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthUserProviderPluginInterface[]
     */
    protected $userProviderPlugins;

    /**
     * @param \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthUserProviderPluginInterface[] $userProviderPlugins
     */
    public function __construct(array $userProviderPlugins = [])
    {
        $this->userProviderPlugins = $userProviderPlugins;
    }

    /**
     * @param string $username
     * @param string $password
     * @param string $grantType The grant type used
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $clientEntity
     *
     * @return \League\OAuth2\Server\Entities\UserEntityInterface
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity
    ) {

        $oauthUserTransfer = $this->createOauthUserTransfer($username, $password, $grantType, $clientEntity);
        $oauthUserTransfer = $this->findUser($oauthUserTransfer);

        if ($oauthUserTransfer && $oauthUserTransfer->getIsSuccess() && $oauthUserTransfer->getUserIdentifier()) {
            return new UserEntity($oauthUserTransfer->getUserIdentifier());
        }

        return null;
    }

    /**
     * @param array $request
     * @param string $grantType The grant type used
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $clientEntity
     *
     * @return \League\OAuth2\Server\Entities\UserEntityInterface|null
     */
    public function getUserEntityByRequest(
        array $request,
        string $grantType,
        ClientEntityInterface $clientEntity
    ): ?UserEntityInterface {

        $oauthUserTransfer = (new OauthUserTransfer())
            ->fromArray($request, true)
            ->setClientId($clientEntity->getIdentifier())
            ->setGrantType($grantType)
            ->setClientName($clientEntity->getName());

        // TODO: need to be solved with generic property using AbstractTransfer
        $oauthUserTransfer->setExampleProperty($request['example_property']);

        $oauthUserTransfer = $this->findUser($oauthUserTransfer);

        if ($oauthUserTransfer && $oauthUserTransfer->getIsSuccess() && $oauthUserTransfer->getUserIdentifier()) {
            return new UserEntity($oauthUserTransfer->getUserIdentifier());
        }

        return null;
    }

    /**
     * @param \Generated\Shared\Transfer\OauthUserTransfer $oauthUserTransfer
     *
     * @return \Generated\Shared\Transfer\OauthUserTransfer|null
     */
    protected function findUser(OauthUserTransfer $oauthUserTransfer): ?OauthUserTransfer
    {
        foreach ($this->userProviderPlugins as $userProviderPlugin) {
            if (!$userProviderPlugin->accept($oauthUserTransfer)) {
                continue;
            }

            $oauthUserTransfer = $userProviderPlugin->getUser($oauthUserTransfer);
            if ($oauthUserTransfer->getIsSuccess()) {
                return $oauthUserTransfer;
            }
        }

        return null;
    }

    /**
     * @param string $username
     * @param string $password
     * @param string $grantType
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $clientEntity
     *
     * @return \Generated\Shared\Transfer\OauthUserTransfer
     */
    protected function createOauthUserTransfer(
        string $username,
        string $password,
        string $grantType,
        ClientEntityInterface $clientEntity
    ): OauthUserTransfer {

        $oauthUserTransfer = new OauthUserTransfer();
        $oauthUserTransfer
            ->setIsSuccess(false)
            ->setUsername($username)
            ->setPassword($password)
            ->setClientId($clientEntity->getIdentifier())
            ->setGrantType($grantType)
            ->setClientName($clientEntity->getName());

        return $oauthUserTransfer;
    }
}
