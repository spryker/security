<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Event\Business;

use Spryker\Shared\Kernel\Transfer\TransferInterface;

/**
 * @method \Spryker\Zed\Event\Business\EventBusinessFactory getFactory()
 */
interface EventFacadeInterface
{
    /**
     * Specification:
     * - Handles all events by registered by give $eventName
     * - Passes eventTransfer to each listener
     * - If listener is queueable then it will put into queue system.
     *
     * @api
     *
     * @param string $eventName
     * @param \Spryker\Shared\Kernel\Transfer\TransferInterface $eventTransfer
     *
     * @return void
     */
    public function trigger($eventName, TransferInterface $eventTransfer);

    /**
     * Specification:
     * - Processes all listeners enqueued in event queue (queue consumer)
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QueueReceiveMessageTransfer[] $queueMessageTransfers
     *
     * @return \Generated\Shared\Transfer\QueueReceiveMessageTransfer[]
     */
    public function processEnqueuedMessages(array $queueMessageTransfers);
}
