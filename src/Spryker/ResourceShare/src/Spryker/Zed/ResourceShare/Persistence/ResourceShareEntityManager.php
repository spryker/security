<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ResourceShare\Persistence;

use Generated\Shared\Transfer\ResourceShareTransfer;
use Spryker\Zed\Kernel\Persistence\AbstractEntityManager;

/**
 * @method \Spryker\Zed\ResourceShare\Persistence\ResourceSharePersistenceFactory getFactory()
 */
class ResourceShareEntityManager extends AbstractEntityManager implements ResourceShareEntityManagerInterface
{
    /**
     * @param \Generated\Shared\Transfer\ResourceShareTransfer $resourceShareTransfer
     *
     * @return \Generated\Shared\Transfer\ResourceShareTransfer
     */
    public function createResourceShare(ResourceShareTransfer $resourceShareTransfer): ResourceShareTransfer
    {
        $resourceShareEntity = $this->getFactory()
            ->createResourceShareMapper()
            ->mapResourceShareTransferToResourceShareEntity($resourceShareTransfer);

        $resourceShareEntity->save();

        $resourceShareTransfer
            ->setIdResourceShare($resourceShareEntity->getIdResourceShare())
            ->setUuid($resourceShareEntity->getUuid());

        return $resourceShareTransfer;
    }

    /**
     * @inheritDoc
     */
    public function buildResourceShare(ResourceShareTransfer $resourceShareTransfer): ResourceShareTransfer
    {
        $resourceShareEntity = $this->getFactory()
            ->createResourceShareMapper()
            ->mapResourceShareTransferToResourceShareEntity($resourceShareTransfer);

        $resourceShareEntity->updateUuid();

        return $resourceShareTransfer
            ->setIdResourceShare($resourceShareEntity->getIdResourceShare())
            ->setUuid($resourceShareEntity->getUuid());
    }
}
