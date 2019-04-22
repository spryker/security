<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Permission;

use Codeception\Actor;
use Spryker\Zed\CompanyRole\Communication\Plugin\PermissionStoragePlugin;

/**
 * Inherited Methods
 * @method void wantToTest($text)
 * @method void wantTo($text)
 * @method void execute($callable)
 * @method void expectTo($prediction)
 * @method void expect($prediction)
 * @method void amGoingTo($argumentation)
 * @method void am($role)
 * @method void lookForwardTo($achieveValue)
 * @method void comment($description)
 * @method \Codeception\Lib\Friend haveFriend($name, $actorClass = NULL)
 *
 * @SuppressWarnings(PHPMD)
 */
class PermissionBusinessTester extends Actor
{
    use _generated\PermissionBusinessTesterActions;

    /**
     * Define custom actions here
     */

    /**
     * @return void
     */
    public function registerPermissionStoragePlugin(): void
    {
        $this->havePermissionStorage(new PermissionStoragePlugin());
    }
}
