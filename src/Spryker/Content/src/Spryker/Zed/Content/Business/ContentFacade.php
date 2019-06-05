<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Content\Business;

use Generated\Shared\Transfer\ContentTransfer;
use Generated\Shared\Transfer\ContentValidationResponseTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\Content\Business\ContentBusinessFactory getFactory()
 * @method \Spryker\Zed\Content\Persistence\ContentEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\Content\Persistence\ContentRepositoryInterface getRepository()
 */
class ContentFacade extends AbstractFacade implements ContentFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idContent
     *
     * @return \Generated\Shared\Transfer\ContentTransfer|null
     */
    public function findContentById(int $idContent): ?ContentTransfer
    {
        return $this->getFactory()->createContentReader()->findContentById($idContent);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $contentKey
     *
     * @return \Generated\Shared\Transfer\ContentTransfer|null
     */
    public function findContentByKey(string $contentKey): ?ContentTransfer
    {
        return $this->getFactory()->createContentReader()->findContentByKey($contentKey);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function create(ContentTransfer $contentTransfer): ContentTransfer
    {
        return $this->getFactory()->createContentWriter()->create($contentTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @throws \Spryker\Shared\Kernel\Transfer\Exception\RequiredTransferPropertyException
     *
     * @return \Generated\Shared\Transfer\ContentTransfer
     */
    public function update(ContentTransfer $contentTransfer): ContentTransfer
    {
        return $this->getFactory()->createContentWriter()->update($contentTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ContentTransfer $contentTransfer
     *
     * @return \Generated\Shared\Transfer\ContentValidationResponseTransfer
     */
    public function validateContent(ContentTransfer $contentTransfer): ContentValidationResponseTransfer
    {
        return $this->getFactory()->createContentValidator()->validateContent($contentTransfer);
    }
}
