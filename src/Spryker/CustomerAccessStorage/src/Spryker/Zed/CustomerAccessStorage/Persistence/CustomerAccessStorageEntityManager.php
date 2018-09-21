<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerAccessStorage\Persistence;

use Generated\Shared\Transfer\CustomerAccessTransfer;
use Spryker\Zed\Kernel\Persistence\AbstractEntityManager;

/**
 * @method \Spryker\Zed\CustomerAccessStorage\Persistence\CustomerAccessStoragePersistenceFactory getFactory()
 */
class CustomerAccessStorageEntityManager extends AbstractEntityManager implements CustomerAccessStorageEntityManagerInterface
{
    /**
     * @param \Generated\Shared\Transfer\CustomerAccessTransfer $customerAccessTransfer
     *
     * @return void
     */
    public function storeData(CustomerAccessTransfer $customerAccessTransfer): void
    {
        $storageEntityTransfer = $this->getFactory()->createCustomerAccessStorageQuery()->findOneOrCreate();
        $storageEntityTransfer->setData($customerAccessTransfer->toArray());
        $storageEntityTransfer->save();
    }
}
