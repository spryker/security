<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Event\Business\Queue\Forwarder;

use Generated\Shared\Transfer\QueueReceiveMessageTransfer;
use Generated\Shared\Transfer\QueueSendMessageTransfer;
use Orm\Zed\Queue\Persistence\Base\SpyQueueProcessQuery;
use Spryker\Shared\Event\EventConstants;
use Spryker\Zed\Event\Dependency\Client\EventToQueueInterface;

class MessageForwarder implements MessageForwarderInterface
{
    /**
     * @var \Spryker\Zed\Event\Dependency\Client\EventToQueueInterface
     */
    protected $queueClient;

    /**
     * @var \Orm\Zed\Queue\Persistence\Base\SpyQueueProcessQuery
     */
    protected $queryContainer;

    /**
     * @param \Spryker\Zed\Event\Dependency\Client\EventToQueueInterface $queueClient
     * @param \Orm\Zed\Queue\Persistence\Base\SpyQueueProcessQuery $queryContainer
     */
    public function __construct(EventToQueueInterface $queueClient, SpyQueueProcessQuery $queryContainer)
    {
        $this->queueClient = $queueClient;
        $this->queryContainer = $queryContainer;
    }

    /**
     * @param \Generated\Shared\Transfer\QueueReceiveMessageTransfer[] $queueMessageTransfers
     *
     * @return \Generated\Shared\Transfer\QueueReceiveMessageTransfer[]
     */
    public function forwardMessages(array $queueMessageTransfers): array
    {
        if ($this->isEventQueueProcessRunning()) {
            return $queueMessageTransfers;
        }

        $responses = [];

        foreach ($queueMessageTransfers as $queueMessageTransfer) {
            $queueMessageTransfer->setAcknowledge(true);
            $this->sendMessage($queueMessageTransfer);

            $responses[] = $queueMessageTransfer;
        }

        return $responses;
    }

    /**
     * @param \Generated\Shared\Transfer\QueueReceiveMessageTransfer $queueMessageTransfer
     *
     * @return void
     */
    protected function sendMessage(QueueReceiveMessageTransfer $queueMessageTransfer): void
    {
        $queueSendMessageTransfer = new QueueSendMessageTransfer();
        $queueSendMessageTransfer->fromArray($queueMessageTransfer->getQueueMessage()->toArray(), true);
        $this->queueClient->sendMessage($queueMessageTransfer->getQueueName(), $queueSendMessageTransfer);
    }

    /**
     * @module Queue
     *
     * @return bool
     */
    protected function isEventQueueProcessRunning(): bool
    {
        return $this->queryContainer
                ->filterByQueueName(EventConstants::EVENT_QUEUE)
                ->count() > 0;
    }
}
