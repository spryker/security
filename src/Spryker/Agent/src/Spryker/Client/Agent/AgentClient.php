<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Agent;

use Generated\Shared\Transfer\UserTransfer;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\Agent\AgentFactory getFactory()
 */
class AgentClient extends AbstractClient implements AgentClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\UserTransfer $userTransfer
     *
     * @return \Generated\Shared\Transfer\UserTransfer
     */
    public function findAgentByUsername(UserTransfer $userTransfer): UserTransfer
    {
        return $this->getFactory()
            ->createZedStub()
            ->findAgentByUsername($userTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return $this->getFactory()
            ->createAgentSession()
            ->isLoggedIn();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\UserTransfer|null
     */
    public function getAgent(): ?UserTransfer
    {
        return $this->getFactory()
            ->createAgentSession()
            ->getAgent();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\UserTransfer $userTransfer
     *
     * @return void
     */
    public function setAgent(UserTransfer $userTransfer): void
    {
        $this->getFactory()
            ->createAgentSession()
            ->setAgent($userTransfer);
    }
}
