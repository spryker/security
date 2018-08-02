<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Agent;

use Generated\Shared\Transfer\CustomerAutocompleteResponseTransfer;
use Generated\Shared\Transfer\CustomerQueryTransfer;
use Generated\Shared\Transfer\UserTransfer;

interface AgentClientInterface
{
    /**
     * Specification:
     * - Returns UserTransfer with an agent.
     * - If username is not exist, an empty transfer will be returned.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\UserTransfer $userTransfer
     *
     * @return \Generated\Shared\Transfer\UserTransfer
     */
    public function findAgentByUsername(UserTransfer $userTransfer): UserTransfer;

    /**
     * Specification:
     * - Returns true if agent auth data exist in session storage.
     *
     * @api
     *
     * @return bool
     */
    public function isLoggedIn(): bool;

    /**
     * Specification:
     * - Returns UserTransfer if an agent logged in, null otherwise.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\UserTransfer|null
     */
    public function getAgent(): ?UserTransfer;

    /**
     * Specification:
     * - Saves UserTransfer into agent's session storage.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\UserTransfer $userTransfer
     *
     * @return void
     */
    public function setAgent(UserTransfer $userTransfer): void;

    /**
     * Specification:
     * - Returns CustomerAutocompleteResponseTransfer with list of customers found by query.
     * - Search works by first name, last name and email.
     * - If customers by query are not exist, collection will be empty.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CustomerQueryTransfer $customerQueryTransfer
     *
     * @return \Generated\Shared\Transfer\CustomerAutocompleteResponseTransfer
     */
    public function findCustomersByQuery(CustomerQueryTransfer $customerQueryTransfer): CustomerAutocompleteResponseTransfer;
}
