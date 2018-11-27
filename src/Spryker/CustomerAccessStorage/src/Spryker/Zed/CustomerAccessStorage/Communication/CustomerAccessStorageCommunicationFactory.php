<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerAccessStorage\Communication;

use Spryker\Zed\Kernel\Communication\AbstractCommunicationFactory;

/**
 * @method \Spryker\Zed\CustomerAccessStorage\CustomerAccessStorageConfig getConfig()
 * @method \Spryker\Zed\CustomerAccessStorage\Persistence\CustomerAccessStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\CustomerAccessStorage\Persistence\CustomerAccessStorageEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\CustomerAccessStorage\Persistence\CustomerAccessStorageRepositoryInterface getRepository()
 * @method \Spryker\Zed\CustomerAccessStorage\Business\CustomerAccessStorageFacadeInterface getFacade()
 */
class CustomerAccessStorageCommunicationFactory extends AbstractCommunicationFactory
{
}
