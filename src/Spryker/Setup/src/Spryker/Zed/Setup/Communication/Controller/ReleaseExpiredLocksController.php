<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Setup\Communication\Controller;

use Spryker\Zed\Kernel\Communication\Controller\AbstractController;

/**
 * @method \Spryker\Zed\Setup\Business\SetupFacadeInterface getFacade()
 * @method \Spryker\Zed\Setup\Communication\SetupCommunicationFactory getFactory()
 */
class ReleaseExpiredLocksController extends AbstractController
{
    /**
     * @return void
     */
    public function indexAction()
    {
    }
}
