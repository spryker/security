<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Oauth\Business\Model;

use Generated\Shared\Transfer\OauthScopeTransfer;

interface OauthScopeReaderInterface
{
    /**
     * @param \Generated\Shared\Transfer\OauthScopeTransfer $oauthScopeTransfer
     *
     * @return \Generated\Shared\Transfer\OauthScopeTransfer|null todo: mb empty transfer
     */
    public function findScopeByIdentifier(OauthScopeTransfer $oauthScopeTransfer): ?OauthScopeTransfer;
}
