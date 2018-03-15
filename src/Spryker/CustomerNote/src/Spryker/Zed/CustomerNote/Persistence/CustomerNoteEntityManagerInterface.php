<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerNote\Persistence;

use Generated\Shared\Transfer\SpyCustomerNoteEntityTransfer;

interface CustomerNoteEntityManagerInterface
{
    /**
     * @param \Generated\Shared\Transfer\SpyCustomerNoteEntityTransfer $customerNoteEntityTransfer
     *
     * @return \Generated\Shared\Transfer\SpyCustomerNoteEntityTransfer
     */
    public function saveNote(SpyCustomerNoteEntityTransfer $customerNoteEntityTransfer): SpyCustomerNoteEntityTransfer;
}
