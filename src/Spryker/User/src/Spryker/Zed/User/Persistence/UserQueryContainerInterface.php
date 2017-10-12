<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\User\Persistence;

interface UserQueryContainerInterface
{
    /**
     * @api
     *
     * @param string $username
     *
     * @return \Orm\Zed\User\Persistence\SpyUserQuery
     */
    public function queryUserByUsername($username);

    /**
     * @api
     *
     * @param int $id
     *
     * @return \Orm\Zed\User\Persistence\SpyUserQuery
     */
    public function queryUserById($id);

    /**
     * @api
     *
     * @return \Orm\Zed\User\Persistence\SpyUserQuery
     */
    public function queryUsers();

    /**
     * @api
     *
     * @return \Orm\Zed\User\Persistence\SpyUserQuery
     */
    public function queryUser();
}
