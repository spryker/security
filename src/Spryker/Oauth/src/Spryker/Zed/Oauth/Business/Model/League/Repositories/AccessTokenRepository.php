<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Oauth\Business\Model\League\Repositories;

use Generated\Shared\Transfer\SpyOauthAccessTokenEntityTransfer;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Spryker\Zed\Oauth\Business\Model\League\Entities\AccessTokenEntity;
use Spryker\Zed\Oauth\Persistence\OauthEntityManagerInterface;
use Spryker\Zed\Oauth\Persistence\OauthRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * @var \Spryker\Zed\Oauth\Persistence\OauthRepositoryInterface
     */
    protected $oauthRepository;

    /**
     * @var \Spryker\Zed\Oauth\Persistence\OauthEntityManagerInterface
     */
    protected $oauthEntityManager;

    /**
     * @var \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthUserIdentifierFilterPluginInterface[]
     */
    protected $oauthUserIdentifierFilterPlugins;

    /**
     * @param \Spryker\Zed\Oauth\Persistence\OauthRepositoryInterface $oauthRepository
     * @param \Spryker\Zed\Oauth\Persistence\OauthEntityManagerInterface $oauthEntityManager
     * @param \Spryker\Zed\OauthExtension\Dependency\Plugin\OauthUserIdentifierFilterPluginInterface[] $oauthUserIdentifierFilterPlugins
     */
    public function __construct(
        OauthRepositoryInterface $oauthRepository,
        OauthEntityManagerInterface $oauthEntityManager,
        array $oauthUserIdentifierFilterPlugins = []
    ) {
        $this->oauthRepository = $oauthRepository;
        $this->oauthEntityManager = $oauthEntityManager;
        $this->oauthUserIdentifierFilterPlugins = [
            new \Spryker\Zed\OauthPermission\Communication\Plugin\Filter\OauthUserIdentifierFilterPermissionPlugin(),
        ];
    }

    /**
     * Create a new access token
     *
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $clientEntity
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @param mixed $userIdentifier
     *
     * @return \League\OAuth2\Server\Entities\AccessTokenEntityInterface
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        $accessToken = new AccessTokenEntity();

        $accessToken->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }
        $accessToken->setUserIdentifier($userIdentifier);

        return $accessToken;
    }

    /**
     * Persists a new access token to permanent storage.
     *
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessTokenEntity
     *
     * @return void
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $userIdentifier = (string)$accessTokenEntity->getUserIdentifier();
        $userIdentifier = $this->filterUserIdentifier($userIdentifier);

        $spyAccessTokenEntityTransfer = new SpyOauthAccessTokenEntityTransfer();
        $spyAccessTokenEntityTransfer
            ->setIdentifier($accessTokenEntity->getIdentifier())
            ->setUserIdentifier($userIdentifier)
            ->setExpirityDate($accessTokenEntity->getExpiryDateTime()->format('Y-m-d H:i:s'))
            ->setFkOauthClient($accessTokenEntity->getClient()->getIdentifier())
            ->setScopes(json_encode($accessTokenEntity->getScopes()));

        $this->oauthEntityManager->saveAccessToken($spyAccessTokenEntityTransfer);
    }

    /**
     * Revoke an access token.
     *
     * @param string $tokenId
     *
     * @return void
     */
    public function revokeAccessToken($tokenId)
    {
        $this->oauthEntityManager->deleteAccessTokenByIdentifier($tokenId);
    }

    /**
     * Check if the access token has been revoked. This would make request to persistence
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isAccessTokenRevoked($tokenId)
    {
        return false;
    }

    /**
     * @param string $userIdentifier
     *
     * @return string
     */
    protected function filterUserIdentifier(string $userIdentifier): string
    {
        //TODO: use encode service
        $decodedUserIdentifier = json_decode($userIdentifier, true);

        if ($decodedUserIdentifier) {
            foreach ($this->oauthUserIdentifierFilterPlugins as $oauthUserIdentifierFilterPlugin) {
                $decodedUserIdentifier = $oauthUserIdentifierFilterPlugin->filter($decodedUserIdentifier);
            }
        }

        return (string)json_encode($decodedUserIdentifier);
    }
}
