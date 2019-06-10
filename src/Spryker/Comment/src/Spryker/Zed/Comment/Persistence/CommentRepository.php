<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Comment\Persistence;

use Generated\Shared\Transfer\CommentFilterTransfer;
use Generated\Shared\Transfer\CommentRequestTransfer;
use Generated\Shared\Transfer\CommentThreadTransfer;
use Generated\Shared\Transfer\CommentTransfer;
use Propel\Runtime\ActiveQuery\Criteria;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;

/**
 * @method \Spryker\Zed\Comment\Persistence\CommentPersistenceFactory getFactory()
 */
class CommentRepository extends AbstractRepository implements CommentRepositoryInterface
{
    /**
     * @module Customer
     *
     * @param \Generated\Shared\Transfer\CommentRequestTransfer $commentRequestTransfer
     *
     * @return \Generated\Shared\Transfer\CommentThreadTransfer|null
     */
    public function findCommentThread(CommentRequestTransfer $commentRequestTransfer): ?CommentThreadTransfer
    {
        $commentRequestTransfer
            ->requireOwnerId()
            ->requireOwnerType();

        $commentThreadEntity = $this->getFactory()
            ->getCommentThreadPropelQuery()
            ->filterByOwnerId($commentRequestTransfer->getOwnerId())
            ->filterByOwnerType($commentRequestTransfer->getOwnerType())
            ->find()
            ->getFirst();

        if (!$commentThreadEntity) {
            return null;
        }

        return $this->getFactory()
            ->createCommentMapper()
            ->mapCommentThreadEntityToCommentThreadTransfer($commentThreadEntity, new CommentThreadTransfer());
    }

    /**
     * @param \Generated\Shared\Transfer\CommentThreadTransfer $commentThreadTransfer
     *
     * @return \Generated\Shared\Transfer\CommentThreadTransfer
     */
    public function getCommentThreadById(CommentThreadTransfer $commentThreadTransfer): CommentThreadTransfer
    {
        $commentThreadTransfer->requireIdCommentThread();

        $commentThreadEntity = $this->getFactory()
            ->getCommentThreadPropelQuery()
            ->filterByIdCommentThread($commentThreadTransfer->getIdCommentThread())
            ->findOne();

        return $this->getFactory()
            ->createCommentMapper()
            ->mapCommentThreadEntityToCommentThreadTransfer($commentThreadEntity, new CommentThreadTransfer());
    }

    /**
     * @param \Generated\Shared\Transfer\CommentThreadTransfer $commentThreadTransfer
     *
     * @return \Generated\Shared\Transfer\CommentTransfer[]
     */
    public function findCommentsByCommentThread(CommentThreadTransfer $commentThreadTransfer): array
    {
        $commentThreadTransfer->requireIdCommentThread();

        $commentEntityCollection = $this->getFactory()
            ->getCommentPropelQuery()
            ->filterByFkCommentThread($commentThreadTransfer->getIdCommentThread())
            ->filterByIsDeleted(false)
            ->joinWithSpyCustomer()
            ->leftJoinWithSpyCommentToCommentTag()
            ->useSpyCommentToCommentTagQuery(null, Criteria::LEFT_JOIN)
                ->leftJoinWithSpyCommentTag()
            ->endUse()
            ->orderByIdComment()
            ->find();

        return $this->getFactory()
            ->createCommentMapper()
            ->mapCommentEntitiesToCommentTransfers($commentEntityCollection);
    }

    /**
     * @param string $uuid
     *
     * @return \Generated\Shared\Transfer\CommentTransfer|null
     */
    public function findCommentByUuid(string $uuid): ?CommentTransfer
    {
        $commentEntity = $this->getFactory()
            ->getCommentPropelQuery()
            ->filterByUuid($uuid)
            ->findOne();

        if (!$commentEntity) {
            return null;
        }

        return $this->getFactory()
            ->createCommentMapper()
            ->mapCommentEntityToCommentTransfer($commentEntity, new CommentTransfer());
    }

    /**
     * @return \Generated\Shared\Transfer\CommentTagTransfer[]
     */
    public function getCommentTags(): array
    {
        $commentTagEntities = $this->getFactory()
            ->getCommentTagPropelQuery()
            ->find();

        return $this->getFactory()
            ->createCommentMapper()
            ->mapCommentTagEntitiesToCommentTagTransfers($commentTagEntities);
    }

    /**
     * @param \Generated\Shared\Transfer\CommentFilterTransfer $commentFilterTransfer
     *
     * @return \Generated\Shared\Transfer\CommentTransfer[]
     */
    public function getCommentsByFilter(CommentFilterTransfer $commentFilterTransfer): array
    {
        $commentFilterTransfer
            ->requireOwnerId()
            ->requireOwnerType();

        $commentQuery = $this->getFactory()
            ->getCommentPropelQuery()
            ->useSpyCommentThreadQuery(null, Criteria::LEFT_JOIN)
                ->filterByOwnerType($commentFilterTransfer->getOwnerType())
                ->filterByOwnerId($commentFilterTransfer->getOwnerId())
            ->endUse()
            ->filterByIsDeleted(false)
            ->joinWithSpyCustomer()
            ->leftJoinWithSpyCommentToCommentTag()
            ->orderByIdComment();

        if ($commentFilterTransfer->getTags()) {
            $commentQuery
                ->useSpyCommentToCommentTagQuery(null, Criteria::LEFT_JOIN)
                    ->leftJoinWithSpyCommentTag()
                    ->useSpyCommentTagQuery(null, Criteria::LEFT_JOIN)
                        ->filterByName_In($commentFilterTransfer->getTags())
                    ->endUse()
                ->endUse();
        }

        return $this->getFactory()
            ->createCommentMapper()
            ->mapCommentEntitiesToCommentTransfers($commentQuery->find());
    }
}
